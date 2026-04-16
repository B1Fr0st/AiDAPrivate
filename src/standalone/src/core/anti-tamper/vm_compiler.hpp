#pragma once


#include <windows.h>
#include <intrin.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "virtualizer.hpp"

namespace anti_tamper {
namespace vm_compiler {

    namespace detail
    {
        inline void advance_rolling_key(uint64_t& key)
        {
            key ^= key << 13;
            key ^= key >> 7;
            key ^= key << 17;
        }

        inline uint8_t encrypt_byte(uint64_t& rolling_key, uint8_t raw)
        {
            uint8_t key_byte = static_cast<uint8_t>(rolling_key & 0xFF);
            advance_rolling_key(rolling_key);
            return raw ^ key_byte;
        }
    }

    class program_t
    {
    public:
        void set_key(uint64_t initial_rolling_key)
        {
            m_rolling_key = initial_rolling_key;
            m_initial_key = initial_rolling_key;
        }

        void set_opcode_map(const uint8_t map[256])
        {
            memcpy(m_opcode_map, map, 256);
        }


        void reset()
        {
            m_bytecode.clear();
            m_rolling_key = m_initial_key;
        }


        void emit_load_imm(uint8_t dst_reg, uint64_t value)
        {
            emit_opcode(virtualizer::detail::OP_LOAD_IMM);
            emit_raw(dst_reg);
            emit_u64(value);
        }


        void emit_load_reg(uint8_t dst_reg, uint8_t src_reg)
        {
            emit_opcode(virtualizer::detail::OP_LOAD_REG);
            emit_raw(dst_reg);
            emit_raw(src_reg);
        }


        void emit_store_reg(uint8_t dst_reg, uint8_t src_reg)
        {
            emit_opcode(virtualizer::detail::OP_STORE_REG);
            emit_raw(dst_reg);
            emit_raw(src_reg);
        }


        void emit_nand(uint8_t dst, uint8_t a, uint8_t b)
        {
            emit_opcode(virtualizer::detail::OP_NAND);
            emit_raw(dst);
            emit_raw(a);
            emit_raw(b);
        }


        void emit_nor(uint8_t dst, uint8_t a, uint8_t b)
        {
            emit_opcode(virtualizer::detail::OP_NOR);
            emit_raw(dst);
            emit_raw(a);
            emit_raw(b);
        }


        void emit_xor(uint8_t dst, uint8_t a, uint8_t b)
        {
            emit_opcode(virtualizer::detail::OP_XOR);
            emit_raw(dst);
            emit_raw(a);
            emit_raw(b);
        }


        void emit_add(uint8_t dst, uint8_t a, uint8_t b)
        {
            emit_opcode(virtualizer::detail::OP_ADD);
            emit_raw(dst);
            emit_raw(a);
            emit_raw(b);
        }


        void emit_sub(uint8_t dst, uint8_t a, uint8_t b)
        {
            emit_opcode(virtualizer::detail::OP_SUB);
            emit_raw(dst);
            emit_raw(a);
            emit_raw(b);
        }


        void emit_shl(uint8_t dst, uint8_t src, uint8_t amount_reg)
        {
            emit_opcode(virtualizer::detail::OP_SHL);
            emit_raw(dst);
            emit_raw(src);
            emit_raw(amount_reg);
        }


        void emit_shr(uint8_t dst, uint8_t src, uint8_t amount_reg)
        {
            emit_opcode(virtualizer::detail::OP_SHR);
            emit_raw(dst);
            emit_raw(src);
            emit_raw(amount_reg);
        }


        void emit_rol(uint8_t dst, uint8_t src, uint8_t amount_reg)
        {
            emit_opcode(virtualizer::detail::OP_ROL);
            emit_raw(dst);
            emit_raw(src);
            emit_raw(amount_reg);
        }


        void emit_ror(uint8_t dst, uint8_t src, uint8_t amount_reg)
        {
            emit_opcode(virtualizer::detail::OP_ROR);
            emit_raw(dst);
            emit_raw(src);
            emit_raw(amount_reg);
        }


        void emit_not(uint8_t dst, uint8_t src)
        {
            emit_opcode(virtualizer::detail::OP_NOT);
            emit_raw(dst);
            emit_raw(src);
        }


        void emit_cmp(uint8_t a, uint8_t b)
        {
            emit_opcode(virtualizer::detail::OP_CMP);
            emit_raw(a);
            emit_raw(b);
        }


        void emit_jmp(uint32_t target)
        {
            emit_opcode(virtualizer::detail::OP_JMP);
            emit_u32(target);
        }


        void emit_jz(uint32_t target)
        {
            emit_opcode(virtualizer::detail::OP_JZ);
            emit_u32(target);
        }


        void emit_jnz(uint32_t target)
        {
            emit_opcode(virtualizer::detail::OP_JNZ);
            emit_u32(target);
        }


        void emit_push(uint8_t src)
        {
            emit_opcode(virtualizer::detail::OP_PUSH);
            emit_raw(src);
        }


        void emit_pop(uint8_t dst)
        {
            emit_opcode(virtualizer::detail::OP_POP);
            emit_raw(dst);
        }


        void emit_hash(uint8_t dst, uint8_t src)
        {
            emit_opcode(virtualizer::detail::OP_HASH);
            emit_raw(dst);
            emit_raw(src);
        }


        void emit_rdtsc(uint8_t dst)
        {
            emit_opcode(virtualizer::detail::OP_RDTSC);
            emit_raw(dst);
        }


        void emit_siphash(uint8_t dst, uint8_t src, uint8_t key_reg)
        {
            emit_opcode(virtualizer::detail::OP_SIPHASH);
            emit_raw(dst);
            emit_raw(src);
            emit_raw(key_reg);
        }


        void emit_verify(uint8_t reg, uint64_t expected)
        {
            emit_opcode(virtualizer::detail::OP_VERIFY);
            emit_raw(reg);
            emit_u64(expected);
        }


        void emit_load_mem(uint8_t dst, uint8_t addr_reg)
        {
            emit_opcode(virtualizer::detail::OP_LOAD_MEM);
            emit_raw(dst);
            emit_raw(addr_reg);
        }


        void emit_store_mem(uint8_t addr_reg, uint8_t src)
        {
            emit_opcode(virtualizer::detail::OP_STORE_MEM);
            emit_raw(addr_reg);
            emit_raw(src);
        }


        void emit_trap()
        {
            emit_opcode(virtualizer::detail::OP_TRAP);
        }


        void emit_halt()
        {
            emit_opcode(virtualizer::detail::OP_HALT);
        }


        void emit_vm_enter()
        {
            emit_opcode(virtualizer::detail::OP_VM_ENTER);
        }


        void emit_vm_exit()
        {
            emit_opcode(virtualizer::detail::OP_VM_EXIT);
        }


        void emit_nop()
        {
            emit_opcode(virtualizer::detail::OP_NOP);
        }


        uint32_t create_label()
        {
            uint32_t id = static_cast<uint32_t>(m_labels.size());
            m_labels.push_back(0);
            return id;
        }


        void bind_label(uint32_t label_id)
        {
            if (label_id < m_labels.size())
                m_labels[label_id] = current_offset();
        }


        void emit_jz_label(uint32_t label_id)
        {
            emit_opcode(virtualizer::detail::OP_JZ);
            m_fixups.push_back({current_offset(), label_id});
            emit_u32(0);
        }


        void emit_jnz_label(uint32_t label_id)
        {
            emit_opcode(virtualizer::detail::OP_JNZ);
            m_fixups.push_back({current_offset(), label_id});
            emit_u32(0);
        }


        void emit_jmp_label(uint32_t label_id)
        {
            emit_opcode(virtualizer::detail::OP_JMP);
            m_fixups.push_back({current_offset(), label_id});
            emit_u32(0);
        }


        void emit_fnv1a_chain(uint8_t dst, const uint8_t* src_regs, uint32_t count)
        {

            emit_load_imm(14, 14695981039346656037ULL);
            emit_load_imm(15, 1099511628211ULL);
            emit_load_reg(dst, 14);

            for (uint32_t i = 0; i < count; ++i)
            {
                emit_xor(dst, dst, src_regs[i]);


                emit_hash(dst, dst);
            }
        }


        void emit_integrity_check(uint64_t value, uint64_t expected_hash)
        {
            emit_load_imm(12, value);
            emit_hash(13, 12);
            emit_verify(13, expected_hash);
        }


        void emit_junk(uint32_t count)
        {
            uint64_t rng = __rdtsc();
            for (uint32_t i = 0; i < count; ++i)
            {
                rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
                uint8_t choice = static_cast<uint8_t>(rng >> 33) % 5;
                switch (choice)
                {
                case 0: emit_nop(); break;
                case 1: emit_load_reg(static_cast<uint8_t>((rng >> 16) % 10) + 6,
                                      static_cast<uint8_t>((rng >> 24) % 10) + 6); break;
                case 2: emit_xor(static_cast<uint8_t>((rng >> 8) % 4) + 10,
                                 static_cast<uint8_t>((rng >> 12) % 4) + 10,
                                 static_cast<uint8_t>((rng >> 20) % 4) + 10); break;
                case 3: emit_not(static_cast<uint8_t>((rng >> 4) % 4) + 10,
                                 static_cast<uint8_t>((rng >> 8) % 4) + 10); break;
                case 4: emit_rdtsc(static_cast<uint8_t>((rng >> 28) % 4) + 10); break;
                }
            }
        }


        uint32_t current_offset() const
        {
            return static_cast<uint32_t>(m_bytecode.size());
        }


        std::vector<uint8_t> finalize()
        {
            if (m_fixups.empty())
                return m_bytecode;


            for (auto& fix : m_fixups)
            {
                uint32_t target = 0;
                if (fix.label_id < m_labels.size())
                    target = m_labels[fix.label_id];


                if (fix.offset + 4 <= m_raw_log.size())
                    memcpy(&m_raw_log[fix.offset], &target, 4);
            }


            m_bytecode.clear();
            m_rolling_key = m_initial_key;
            for (uint8_t b : m_raw_log)
                m_bytecode.push_back(detail::encrypt_byte(m_rolling_key, b));

            return m_bytecode;
        }

    private:
        std::vector<uint8_t> m_bytecode;
        std::vector<uint8_t> m_raw_log;
        uint64_t             m_rolling_key = 0;
        uint64_t             m_initial_key = 0;
        uint8_t              m_opcode_map[256] = {};

        struct fixup_t
        {
            uint32_t offset;
            uint32_t label_id;
        };

        std::vector<uint32_t> m_labels;
        std::vector<fixup_t>  m_fixups;

        void emit_opcode(uint8_t raw_opcode)
        {
            uint8_t mapped = m_opcode_map[raw_opcode];
            m_raw_log.push_back(mapped);
            m_bytecode.push_back(detail::encrypt_byte(m_rolling_key, mapped));
        }

        void emit_raw(uint8_t byte)
        {
            m_raw_log.push_back(byte);
            m_bytecode.push_back(detail::encrypt_byte(m_rolling_key, byte));
        }

        void emit_u32(uint32_t val)
        {
            uint8_t buf[4];
            memcpy(buf, &val, 4);
            for (int i = 0; i < 4; ++i)
                emit_raw(buf[i]);
        }

        void emit_u64(uint64_t val)
        {
            uint8_t buf[8];
            memcpy(buf, &val, 8);
            for (int i = 0; i < 8; ++i)
                emit_raw(buf[i]);
        }
    };


    inline std::vector<uint8_t> build_hwid_verify_program(
        uint64_t expected_hwid_hash,
        uint64_t initial_key,
        const uint8_t opcode_map[256])
    {
        program_t prog;
        prog.set_key(initial_key);
        prog.set_opcode_map(opcode_map);

        auto label_ok   = prog.create_label();
        auto label_fail = prog.create_label();

        prog.emit_vm_enter();


        prog.emit_junk(3);


        prog.emit_load_imm(5, 14695981039346656037ULL);

        prog.emit_xor(5, 5, 0);
        prog.emit_hash(5, 5);

        prog.emit_xor(5, 5, 1);
        prog.emit_hash(5, 5);

        prog.emit_xor(5, 5, 2);
        prog.emit_hash(5, 5);


        prog.emit_junk(2);


        prog.emit_load_imm(6, expected_hwid_hash);
        prog.emit_cmp(5, 6);
        prog.emit_jz_label(label_ok);
        prog.emit_jmp_label(label_fail);

        prog.bind_label(label_fail);
        prog.emit_trap();

        prog.bind_label(label_ok);
        prog.emit_load_imm(0, 1);
        prog.emit_junk(2);
        prog.emit_vm_exit();
        prog.emit_halt();

        return prog.finalize();
    }


    inline std::vector<uint8_t> build_proof_token_program(
        uint64_t session_seed,
        uint64_t initial_key,
        const uint8_t opcode_map[256])
    {
        program_t prog;
        prog.set_key(initial_key);
        prog.set_opcode_map(opcode_map);

        prog.emit_vm_enter();
        prog.emit_junk(2);


        prog.emit_load_imm(5, session_seed);


        prog.emit_xor(5, 5, 0);

        prog.emit_load_imm(8, 13);
        prog.emit_rol(5, 5, 8);

        prog.emit_xor(5, 5, 1);

        prog.emit_load_imm(8, 29);
        prog.emit_rol(5, 5, 8);

        prog.emit_xor(5, 5, 2);
        prog.emit_junk(2);

        prog.emit_xor(5, 5, 3);

        prog.emit_hash(5, 5);


        prog.emit_load_reg(0, 5);
        prog.emit_vm_exit();
        prog.emit_halt();

        return prog.finalize();
    }


    inline std::vector<uint8_t> build_integrity_check_program(
        uint64_t expected_code_hash,
        uint64_t code_base_addr,
        uint64_t code_size,
        uint64_t initial_key,
        const uint8_t opcode_map[256])
    {
        program_t prog;
        prog.set_key(initial_key);
        prog.set_opcode_map(opcode_map);

        auto label_loop = prog.create_label();
        auto label_done = prog.create_label();
        auto label_fail = prog.create_label();
        auto label_ok   = prog.create_label();

        prog.emit_vm_enter();


        prog.emit_load_imm(0, 14695981039346656037ULL);

        prog.emit_load_imm(1, code_base_addr);

        prog.emit_load_imm(2, code_base_addr + code_size);

        prog.emit_load_imm(3, 1099511628211ULL);


        prog.bind_label(label_loop);
        prog.emit_cmp(1, 2);
        prog.emit_jz_label(label_done);


        prog.emit_load_mem(4, 1);

        prog.emit_xor(0, 0, 4);

        prog.emit_hash(0, 0);

        prog.emit_load_imm(5, 8);
        prog.emit_add(1, 1, 5);

        prog.emit_jmp_label(label_loop);

        prog.bind_label(label_done);

        prog.emit_load_imm(6, expected_code_hash);
        prog.emit_cmp(0, 6);
        prog.emit_jz_label(label_ok);

        prog.bind_label(label_fail);
        prog.emit_load_imm(0, 0);
        prog.emit_vm_exit();
        prog.emit_halt();

        prog.bind_label(label_ok);
        prog.emit_load_imm(0, 1);
        prog.emit_vm_exit();
        prog.emit_halt();

        return prog.finalize();
    }

}
}
