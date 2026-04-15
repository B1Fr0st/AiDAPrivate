#pragma once

#include <windows.h>
#include <intrin.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <functional>
#include <mutex>
#include <vector>

#include "../../obfuscation.hpp"

namespace standalone_virtualizer
{

namespace detail
{

    struct vm_opcode_entry
    {
        uint8_t mapped_op;
        uint8_t real_op;
    };

    struct vm_state_t
    {
        uint64_t regs[16];
        uint64_t rsp;
        uint64_t rip;
        uint64_t flags;
        uint8_t* stack;
        uint32_t stack_size;
        uint8_t opcode_map[256];
        uint8_t reverse_map[256];
        bool halted;
    };

    enum vm_ops : uint8_t
    {
        OP_NOP = 0x00,
        OP_LOAD_IMM = 0x01,
        OP_LOAD_REG = 0x02,
        OP_STORE_REG = 0x03,
        OP_ADD = 0x04,
        OP_SUB = 0x05,
        OP_XOR = 0x06,
        OP_AND = 0x07,
        OP_OR = 0x08,
        OP_NOT = 0x09,
        OP_SHL = 0x0A,
        OP_SHR = 0x0B,
        OP_ROL = 0x0C,
        OP_ROR = 0x0D,
        OP_CMP = 0x0E,
        OP_JMP = 0x0F,
        OP_JZ = 0x10,
        OP_JNZ = 0x11,
        OP_CALL = 0x12,
        OP_RET = 0x13,
        OP_PUSH = 0x14,
        OP_POP = 0x15,
        OP_MUL = 0x16,
        OP_DIV = 0x17,
        OP_MOD = 0x18,
        OP_LOAD_MEM = 0x19,
        OP_STORE_MEM = 0x1A,
        OP_SYSCALL = 0x1B,
        OP_RDTSC = 0x1C,
        OP_CRC32 = 0x1D,
        OP_HALT = 0x1E,
        OP_TRAP = 0x1F,
        OP_OBFUSCATE = 0x20,
        OP_DEOBFUSCATE = 0x21,
        OP_VERIFY = 0x22,
        OP_MAX
    };

    inline void generate_opcode_map(uint64_t seed, uint8_t* map, uint8_t* reverse)
    {
        for (int i = 0; i < 256; ++i)
            map[i] = static_cast<uint8_t>(i);

        uint64_t state = seed;
        for (int i = 255; i > 0; --i)
        {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            int j = static_cast<int>(state % (i + 1));
            uint8_t tmp = map[i];
            map[i] = map[j];
            map[j] = tmp;
        }

        for (int i = 0; i < 256; ++i)
            reverse[map[i]] = static_cast<uint8_t>(i);
    }

    inline void init_vm(vm_state_t& vm, uint64_t seed)
    {
        memset(&vm, 0, sizeof(vm));
        vm.stack_size = 4096;
        vm.stack = new uint8_t[vm.stack_size];
        memset(vm.stack, 0, vm.stack_size);
        vm.rsp = vm.stack_size;
        vm.halted = false;
        generate_opcode_map(seed, vm.opcode_map, vm.reverse_map);
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
    }

    inline uint64_t vm_execute(vm_state_t& vm, const uint8_t* bytecode, uint32_t bc_size)
    {
        vm.rip = 0;
        vm.halted = false;
        uint32_t max_insn = 100000;
        uint32_t executed = 0;

        while (!vm.halted && vm.rip < bc_size && executed < max_insn)
        {
            uint8_t raw = bytecode[vm.rip];
            uint8_t op = vm.reverse_map[raw];

            ++vm.rip;
            ++executed;

            switch (op)
            {
            case OP_NOP:
                break;

            case OP_LOAD_IMM:
            {
                if (vm.rip + 9 > bc_size) { vm.halted = true; break; }
                uint8_t reg = bytecode[vm.rip++] & 0x0F;
                uint64_t val;
                memcpy(&val, bytecode + vm.rip, 8);
                vm.rip += 8;
                vm.regs[reg] = val;
                break;
            }

            case OP_LOAD_REG:
            {
                if (vm.rip + 2 > bc_size) { vm.halted = true; break; }
                uint8_t dst = bytecode[vm.rip++] & 0x0F;
                uint8_t src = bytecode[vm.rip++] & 0x0F;
                vm.regs[dst] = vm.regs[src];
                break;
            }

            case OP_STORE_REG:
            {
                if (vm.rip + 2 > bc_size) { vm.halted = true; break; }
                uint8_t dst = bytecode[vm.rip++] & 0x0F;
                uint8_t src = bytecode[vm.rip++] & 0x0F;
                vm.regs[dst] = vm.regs[src];
                break;
            }

            case OP_ADD:
            {
                if (vm.rip + 2 > bc_size) { vm.halted = true; break; }
                uint8_t a = bytecode[vm.rip++] & 0x0F;
                uint8_t b = bytecode[vm.rip++] & 0x0F;
                vm.regs[a] += vm.regs[b];
                vm.flags = (vm.regs[a] == 0) ? 1 : 0;
                break;
            }

            case OP_SUB:
            {
                if (vm.rip + 2 > bc_size) { vm.halted = true; break; }
                uint8_t a = bytecode[vm.rip++] & 0x0F;
                uint8_t b = bytecode[vm.rip++] & 0x0F;
                vm.regs[a] -= vm.regs[b];
                vm.flags = (vm.regs[a] == 0) ? 1 : 0;
                break;
            }

            case OP_XOR:
            {
                if (vm.rip + 2 > bc_size) { vm.halted = true; break; }
                uint8_t a = bytecode[vm.rip++] & 0x0F;
                uint8_t b = bytecode[vm.rip++] & 0x0F;
                vm.regs[a] ^= vm.regs[b];
                vm.flags = (vm.regs[a] == 0) ? 1 : 0;
                break;
            }

            case OP_AND:
            {
                if (vm.rip + 2 > bc_size) { vm.halted = true; break; }
                uint8_t a = bytecode[vm.rip++] & 0x0F;
                uint8_t b = bytecode[vm.rip++] & 0x0F;
                vm.regs[a] &= vm.regs[b];
                vm.flags = (vm.regs[a] == 0) ? 1 : 0;
                break;
            }

            case OP_OR:
            {
                if (vm.rip + 2 > bc_size) { vm.halted = true; break; }
                uint8_t a = bytecode[vm.rip++] & 0x0F;
                uint8_t b = bytecode[vm.rip++] & 0x0F;
                vm.regs[a] |= vm.regs[b];
                vm.flags = (vm.regs[a] == 0) ? 1 : 0;
                break;
            }

            case OP_NOT:
            {
                if (vm.rip + 1 > bc_size) { vm.halted = true; break; }
                uint8_t a = bytecode[vm.rip++] & 0x0F;
                vm.regs[a] = ~vm.regs[a];
                break;
            }

            case OP_SHL:
            {
                if (vm.rip + 2 > bc_size) { vm.halted = true; break; }
                uint8_t a = bytecode[vm.rip++] & 0x0F;
                uint8_t b = bytecode[vm.rip++] & 0x3F;
                vm.regs[a] <<= b;
                break;
            }

            case OP_SHR:
            {
                if (vm.rip + 2 > bc_size) { vm.halted = true; break; }
                uint8_t a = bytecode[vm.rip++] & 0x0F;
                uint8_t b = bytecode[vm.rip++] & 0x3F;
                vm.regs[a] >>= b;
                break;
            }

            case OP_ROL:
            {
                if (vm.rip + 2 > bc_size) { vm.halted = true; break; }
                uint8_t a = bytecode[vm.rip++] & 0x0F;
                uint8_t b = bytecode[vm.rip++] & 0x3F;
                vm.regs[a] = _rotl64(vm.regs[a], b);
                break;
            }

            case OP_ROR:
            {
                if (vm.rip + 2 > bc_size) { vm.halted = true; break; }
                uint8_t a = bytecode[vm.rip++] & 0x0F;
                uint8_t b = bytecode[vm.rip++] & 0x3F;
                vm.regs[a] = _rotr64(vm.regs[a], b);
                break;
            }

            case OP_CMP:
            {
                if (vm.rip + 2 > bc_size) { vm.halted = true; break; }
                uint8_t a = bytecode[vm.rip++] & 0x0F;
                uint8_t b = bytecode[vm.rip++] & 0x0F;
                vm.flags = (vm.regs[a] == vm.regs[b]) ? 1 : 0;
                break;
            }

            case OP_JMP:
            {
                if (vm.rip + 4 > bc_size) { vm.halted = true; break; }
                uint32_t target;
                memcpy(&target, bytecode + vm.rip, 4);
                vm.rip = target;
                break;
            }

            case OP_JZ:
            {
                if (vm.rip + 4 > bc_size) { vm.halted = true; break; }
                uint32_t target;
                memcpy(&target, bytecode + vm.rip, 4);
                vm.rip += 4;
                if (vm.flags == 1) vm.rip = target;
                break;
            }

            case OP_JNZ:
            {
                if (vm.rip + 4 > bc_size) { vm.halted = true; break; }
                uint32_t target;
                memcpy(&target, bytecode + vm.rip, 4);
                vm.rip += 4;
                if (vm.flags != 1) vm.rip = target;
                break;
            }

            case OP_PUSH:
            {
                if (vm.rip + 1 > bc_size) { vm.halted = true; break; }
                uint8_t r = bytecode[vm.rip++] & 0x0F;
                if (vm.rsp < 8) { vm.halted = true; break; }
                vm.rsp -= 8;
                memcpy(vm.stack + vm.rsp, &vm.regs[r], 8);
                break;
            }

            case OP_POP:
            {
                if (vm.rip + 1 > bc_size) { vm.halted = true; break; }
                uint8_t r = bytecode[vm.rip++] & 0x0F;
                if (vm.rsp + 8 > vm.stack_size) { vm.halted = true; break; }
                memcpy(&vm.regs[r], vm.stack + vm.rsp, 8);
                vm.rsp += 8;
                break;
            }

            case OP_MUL:
            {
                if (vm.rip + 2 > bc_size) { vm.halted = true; break; }
                uint8_t a = bytecode[vm.rip++] & 0x0F;
                uint8_t b = bytecode[vm.rip++] & 0x0F;
                vm.regs[a] *= vm.regs[b];
                break;
            }

            case OP_RDTSC:
            {
                if (vm.rip + 1 > bc_size) { vm.halted = true; break; }
                uint8_t r = bytecode[vm.rip++] & 0x0F;
                vm.regs[r] = __rdtsc();
                break;
            }

            case OP_CRC32:
            {
                if (vm.rip + 2 > bc_size) { vm.halted = true; break; }
                uint8_t dst = bytecode[vm.rip++] & 0x0F;
                uint8_t src = bytecode[vm.rip++] & 0x0F;
                vm.regs[dst] = _mm_crc32_u64(vm.regs[dst], vm.regs[src]);
                break;
            }

            case OP_VERIFY:
            {
                if (vm.rip + 2 > bc_size) { vm.halted = true; break; }
                uint8_t a = bytecode[vm.rip++] & 0x0F;
                uint8_t b = bytecode[vm.rip++] & 0x0F;
                if (vm.regs[a] != vm.regs[b])
                {
                    vm.regs[0] = 0xDEADBEEFDEADBEEFULL;
                    vm.halted = true;
                }
                break;
            }

            case OP_TRAP:
                vm.regs[0] = 0xDEADBEEFDEADBEEFULL;
                vm.halted = true;
                break;

            case OP_HALT:
                vm.halted = true;
                break;

            default:
                vm.regs[0] = 0xDEADBEEFDEADBEEFULL;
                vm.halted = true;
                break;
            }
        }

        return vm.regs[0];
    }

}


namespace integrity_vm
{

    struct vm_check_t
    {
        detail::vm_state_t vm;
        std::vector<uint8_t> bytecode;
        uint64_t expected_result;
        bool initialized;
    };

    inline vm_check_t& get_checker()
    {
        static vm_check_t c{};
        return c;
    }

    inline void emit_byte(std::vector<uint8_t>& bc, uint8_t val, const uint8_t* map)
    {
        bc.push_back(map[val]);
    }

    inline void emit_load_imm(std::vector<uint8_t>& bc, uint8_t reg, uint64_t val, const uint8_t* map)
    {
        bc.push_back(map[detail::OP_LOAD_IMM]);
        bc.push_back(reg);
        uint8_t bytes[8];
        memcpy(bytes, &val, 8);
        for (int i = 0; i < 8; ++i)
            bc.push_back(bytes[i]);
    }

    inline void emit_op2(std::vector<uint8_t>& bc, uint8_t op, uint8_t a, uint8_t b, const uint8_t* map)
    {
        bc.push_back(map[op]);
        bc.push_back(a);
        bc.push_back(b);
    }

    inline void emit_op1(std::vector<uint8_t>& bc, uint8_t op, uint8_t a, const uint8_t* map)
    {
        bc.push_back(map[op]);
        bc.push_back(a);
    }

    inline bool build_integrity_check(uint64_t code_base, uint32_t code_size, uint64_t text_hash)
    {
        auto& c = get_checker();

        uint64_t seed = __rdtsc() ^ reinterpret_cast<uint64_t>(&c) ^ GetCurrentProcessId();
        detail::init_vm(c.vm, seed);
        c.bytecode.clear();

        auto& bc = c.bytecode;
        auto* map = c.vm.opcode_map;

        emit_load_imm(bc, 0, 0xFFFFFFFFULL, map);
        emit_load_imm(bc, 1, 0x85EBCA6BULL, map);
        emit_load_imm(bc, 2, code_base, map);
        emit_load_imm(bc, 3, static_cast<uint64_t>(code_size / 8), map);
        emit_load_imm(bc, 4, 0, map);
        emit_load_imm(bc, 5, 0xA5A5A5A5A5A5A5A5ULL, map);
        emit_load_imm(bc, 6, 8, map);

        uint32_t loop_start = static_cast<uint32_t>(bc.size());

        emit_op2(bc, detail::OP_CMP, 4, 3, map);
        uint32_t jz_pos = static_cast<uint32_t>(bc.size());
        bc.push_back(map[detail::OP_JZ]);
        uint32_t jz_target_pos = static_cast<uint32_t>(bc.size());
        bc.push_back(0); bc.push_back(0); bc.push_back(0); bc.push_back(0);

        emit_load_imm(bc, 7, 0, map);
        emit_op2(bc, detail::OP_CRC32, 0, 7, map);

        emit_op2(bc, detail::OP_LOAD_REG, 8, 7, map);
        emit_op2(bc, detail::OP_XOR, 8, 5, map);
        emit_op2(bc, detail::OP_CRC32, 1, 8, map);

        emit_load_imm(bc, 9, 1, map);
        emit_op2(bc, detail::OP_ADD, 4, 9, map);

        emit_op2(bc, detail::OP_ADD, 2, 6, map);

        bc.push_back(map[detail::OP_JMP]);
        uint8_t ls_bytes[4];
        memcpy(ls_bytes, &loop_start, 4);
        bc.push_back(ls_bytes[0]); bc.push_back(ls_bytes[1]);
        bc.push_back(ls_bytes[2]); bc.push_back(ls_bytes[3]);

        uint32_t loop_end = static_cast<uint32_t>(bc.size());
        memcpy(bc.data() + jz_target_pos, &loop_end, 4);

        emit_load_imm(bc, 10, 32, map);
        emit_op2(bc, detail::OP_LOAD_REG, 11, 0, map);
        bc.push_back(map[detail::OP_SHR]);
        bc.push_back(11);
        bc.push_back(0);

        emit_op2(bc, detail::OP_LOAD_REG, 12, 1, map);
        emit_op1(bc, detail::OP_SHL, 12, map);
        bc.push_back(32);

        emit_op2(bc, detail::OP_AND, 0, 12, map);

        emit_load_imm(bc, 13, 0xFFFFFFFF, map);
        emit_op2(bc, detail::OP_AND, 0, 13, map);
        emit_op2(bc, detail::OP_AND, 12, 13, map);
        emit_op2(bc, detail::OP_OR, 0, 12, map);

        bc.push_back(map[detail::OP_HALT]);

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
        c.vm.flags = 0;
        c.vm.halted = false;

        return detail::vm_execute(c.vm, c.bytecode.data(),
            static_cast<uint32_t>(c.bytecode.size()));
    }

}


namespace control_flow
{

    using handler_fn_t = std::function<void()>;

    struct dispatch_entry_t
    {
        uint32_t id;
        handler_fn_t handler;
    };

    struct flattened_block_t
    {
        std::vector<dispatch_entry_t> entries;
        uint32_t state;
        uint64_t dispatch_key;
    };

    inline flattened_block_t& get_dispatch()
    {
        static flattened_block_t d;
        return d;
    }

    inline uint32_t scramble_state(uint32_t state, uint64_t key)
    {
        uint32_t h = state ^ static_cast<uint32_t>(key);
        h = ((h >> 16) ^ h) * 0x45d9f3bu;
        h = ((h >> 16) ^ h) * 0x45d9f3bu;
        h = (h >> 16) ^ h;
        return h;
    }

    inline void register_block(uint32_t id, handler_fn_t fn)
    {
        auto& d = get_dispatch();
        d.entries.push_back({id, std::move(fn)});
    }

    inline void execute_sequence(const std::vector<uint32_t>& sequence)
    {
        auto& d = get_dispatch();
        for (uint32_t target : sequence)
        {
            uint32_t scrambled = scramble_state(target, d.dispatch_key);
            for (auto& e : d.entries)
            {
                uint32_t entry_scrambled = scramble_state(e.id, d.dispatch_key);
                if (entry_scrambled == scrambled)
                {
                    e.handler();
                    break;
                }
            }
        }
    }

    inline void init_dispatch(uint64_t key)
    {
        auto& d = get_dispatch();
        d.dispatch_key = key;
        d.state = 0;
    }

}


namespace opaque
{

    __forceinline bool predicate_always_true(uint64_t x)
    {
        return (x * x + x) % 2 == 0;
    }

    __forceinline bool predicate_always_false(uint64_t x)
    {
        return (x * x * x + 1) % 2 == 0 && (x % 2 == 1);
    }

    __forceinline uint64_t opaque_constant(uint64_t val, uint64_t noise)
    {
        uint64_t a = (noise * noise + noise);
        uint64_t b = a % 2;
        return val + b;
    }

    __forceinline uint64_t opaque_zero(uint64_t noise)
    {
        return (noise ^ noise) & ((noise * 0) | 0);
    }

}


namespace junk
{

    __declspec(noinline) volatile int dead_computation_a(volatile int seed)
    {
        volatile int x = seed ^ 0x5A5A;
        for (volatile int i = 0; i < 1; ++i)
        {
            x = (x * 1103515245 + 12345) & 0x7FFFFFFF;
            x ^= x >> 16;
        }
        return x;
    }

    __declspec(noinline) volatile int dead_computation_b(volatile int seed)
    {
        volatile int x = seed;
        x = ((x << 13) ^ x) - (x >> 21);
        x = ((x << 5) ^ x) + (x >> 3);
        return x;
    }

    __declspec(noinline) void insert_junk_sled()
    {
        volatile int a = dead_computation_a(static_cast<int>(__rdtsc() & 0xFF));
        volatile int b = dead_computation_b(a);
        volatile int c = a ^ b;
        (void)c;
    }

}


inline bool initialize(uint64_t code_base, uint32_t code_size, uint64_t text_hash)
{
    uint64_t dispatch_key = __rdtsc() ^ GetCurrentProcessId();
    control_flow::init_dispatch(dispatch_key);

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

}
