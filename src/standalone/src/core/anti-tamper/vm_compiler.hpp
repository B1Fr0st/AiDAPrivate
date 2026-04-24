#pragma once


#include <windows.h>
#include <intrin.h>

#include <cstdint>
#include <cstring>
#include <vector>
#include <unordered_map>

#ifdef AIDA_STANDALONE
#include <Zydis/Zydis.h>
#endif

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

        inline uint64_t derive_block_key(uint64_t saved_key, uint32_t target)
        {
            uint64_t k = saved_key ^ static_cast<uint64_t>(target);
            k ^= k >> 30;
            k *= 0xBF58476D1CE4E5B9ULL;
            k ^= k >> 27;
            k *= 0x94D049BB133111EBULL;
            k ^= k >> 31;
            return k;
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

        void emit_load_imm8(uint8_t dst_reg, uint8_t value)
        {
            emit_opcode(virtualizer::detail::OP_LOAD_IMM8);
            emit_raw(dst_reg);
            emit_raw(value);
        }

        void emit_load_imm16(uint8_t dst_reg, uint16_t value)
        {
            emit_opcode(virtualizer::detail::OP_LOAD_IMM16);
            emit_raw(dst_reg);
            emit_raw(static_cast<uint8_t>(value & 0xFF));
            emit_raw(static_cast<uint8_t>((value >> 8) & 0xFF));
        }

        void emit_load_imm32(uint8_t dst_reg, uint32_t value)
        {
            emit_opcode(virtualizer::detail::OP_LOAD_IMM32);
            emit_raw(dst_reg);
            emit_u32(value);
        }

        void emit_mul(uint8_t dst, uint8_t src)
        {
            emit_opcode(virtualizer::detail::OP_MUL);
            emit_raw(dst);
            emit_raw(src);
        }

        void emit_imul(uint8_t dst, uint8_t src)
        {
            emit_opcode(virtualizer::detail::OP_IMUL);
            emit_raw(dst);
            emit_raw(src);
        }

        void emit_div(uint8_t dst, uint8_t src)
        {
            emit_opcode(virtualizer::detail::OP_DIV);
            emit_raw(dst);
            emit_raw(src);
        }

        void emit_idiv(uint8_t dst, uint8_t src)
        {
            emit_opcode(virtualizer::detail::OP_IDIV);
            emit_raw(dst);
            emit_raw(src);
        }

        void emit_cmov(uint8_t cc, uint8_t dst, uint8_t src)
        {
            emit_opcode(virtualizer::detail::OP_CMOV);
            emit_raw(static_cast<uint8_t>((cc << 4) | (dst & 0x0F)));
            emit_raw(src);
        }

        void emit_setcc(uint8_t cc, uint8_t dst)
        {
            emit_opcode(virtualizer::detail::OP_SETCC);
            emit_raw(static_cast<uint8_t>((cc << 4) | (dst & 0x0F)));
        }

        void emit_vcall(uint32_t target)
        {
            emit_opcode(virtualizer::detail::OP_VCALL);
            emit_u32(target);
        }

        void emit_vret()
        {
            emit_opcode(virtualizer::detail::OP_VRET);
        }

        void emit_jl(uint32_t target)
        {
            emit_opcode(virtualizer::detail::OP_JL);
            emit_u32(target);
        }

        void emit_jle(uint32_t target)
        {
            emit_opcode(virtualizer::detail::OP_JLE);
            emit_u32(target);
        }

        void emit_jg(uint32_t target)
        {
            emit_opcode(virtualizer::detail::OP_JG);
            emit_u32(target);
        }

        void emit_jge(uint32_t target)
        {
            emit_opcode(virtualizer::detail::OP_JGE);
            emit_u32(target);
        }

        void emit_jb(uint32_t target)
        {
            emit_opcode(virtualizer::detail::OP_JB);
            emit_u32(target);
        }

        void emit_jbe(uint32_t target)
        {
            emit_opcode(virtualizer::detail::OP_JBE);
            emit_u32(target);
        }

        void emit_js(uint32_t target)
        {
            emit_opcode(virtualizer::detail::OP_JS);
            emit_u32(target);
        }

        void emit_jo(uint32_t target)
        {
            emit_opcode(virtualizer::detail::OP_JO);
            emit_u32(target);
        }

        void emit_jnb(uint32_t target)
        {
            emit_opcode(virtualizer::detail::OP_JNB);
            emit_u32(target);
        }

        void emit_jnbe(uint32_t target)
        {
            emit_opcode(virtualizer::detail::OP_JNBE);
            emit_u32(target);
        }

        void emit_lahf(uint8_t dst)
        {
            emit_opcode(virtualizer::detail::OP_LAHF);
            emit_raw(dst);
        }

        void emit_sahf(uint8_t src)
        {
            emit_opcode(virtualizer::detail::OP_SAHF);
            emit_raw(src);
        }

        void emit_jl_label(uint32_t label_id)
        {
            emit_opcode(virtualizer::detail::OP_JL);
            m_fixups.push_back({current_offset(), label_id});
            emit_u32(0);
        }

        void emit_jle_label(uint32_t label_id)
        {
            emit_opcode(virtualizer::detail::OP_JLE);
            m_fixups.push_back({current_offset(), label_id});
            emit_u32(0);
        }

        void emit_jg_label(uint32_t label_id)
        {
            emit_opcode(virtualizer::detail::OP_JG);
            m_fixups.push_back({current_offset(), label_id});
            emit_u32(0);
        }

        void emit_jge_label(uint32_t label_id)
        {
            emit_opcode(virtualizer::detail::OP_JGE);
            m_fixups.push_back({current_offset(), label_id});
            emit_u32(0);
        }

        void emit_jb_label(uint32_t label_id)
        {
            emit_opcode(virtualizer::detail::OP_JB);
            m_fixups.push_back({current_offset(), label_id});
            emit_u32(0);
        }

        void emit_jbe_label(uint32_t label_id)
        {
            emit_opcode(virtualizer::detail::OP_JBE);
            m_fixups.push_back({current_offset(), label_id});
            emit_u32(0);
        }

        void emit_js_label(uint32_t label_id)
        {
            emit_opcode(virtualizer::detail::OP_JS);
            m_fixups.push_back({current_offset(), label_id});
            emit_u32(0);
        }

        void emit_jo_label(uint32_t label_id)
        {
            emit_opcode(virtualizer::detail::OP_JO);
            m_fixups.push_back({current_offset(), label_id});
            emit_u32(0);
        }

        void emit_jnb_label(uint32_t label_id)
        {
            emit_opcode(virtualizer::detail::OP_JNB);
            m_fixups.push_back({current_offset(), label_id});
            emit_u32(0);
        }

        void emit_jnbe_label(uint32_t label_id)
        {
            emit_opcode(virtualizer::detail::OP_JNBE);
            m_fixups.push_back({current_offset(), label_id});
            emit_u32(0);
        }

        void emit_vcall_label(uint32_t label_id)
        {
            emit_opcode(virtualizer::detail::OP_VCALL);
            m_fixups.push_back({current_offset(), label_id});
            emit_u32(0);
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

#ifdef AIDA_STANDALONE
namespace x86_lifter {

    static constexpr uint8_t VREG_RAX = 0;
    static constexpr uint8_t VREG_RCX = 1;
    static constexpr uint8_t VREG_RDX = 2;
    static constexpr uint8_t VREG_RBX = 3;
    static constexpr uint8_t VREG_RSP = 4;
    static constexpr uint8_t VREG_RBP = 5;
    static constexpr uint8_t VREG_RSI = 6;
    static constexpr uint8_t VREG_RDI = 7;
    static constexpr uint8_t VREG_R8  = 8;
    static constexpr uint8_t VREG_R9  = 9;
    static constexpr uint8_t VREG_SCRATCH0 = 10;
    static constexpr uint8_t VREG_SCRATCH1 = 11;
    static constexpr uint8_t VREG_SCRATCH2 = 12;
    static constexpr uint8_t VREG_SCRATCH3 = 13;
    static constexpr uint8_t VREG_KEY0     = 14;
    static constexpr uint8_t VREG_KEY1     = 15;

    inline uint8_t zydis_reg_to_vreg(ZydisRegister reg)
    {
        switch (reg) {
        case ZYDIS_REGISTER_RAX: case ZYDIS_REGISTER_EAX: case ZYDIS_REGISTER_AX:
        case ZYDIS_REGISTER_AL:  case ZYDIS_REGISTER_AH:  return VREG_RAX;
        case ZYDIS_REGISTER_RCX: case ZYDIS_REGISTER_ECX: case ZYDIS_REGISTER_CX:
        case ZYDIS_REGISTER_CL:  case ZYDIS_REGISTER_CH:  return VREG_RCX;
        case ZYDIS_REGISTER_RDX: case ZYDIS_REGISTER_EDX: case ZYDIS_REGISTER_DX:
        case ZYDIS_REGISTER_DL:  case ZYDIS_REGISTER_DH:  return VREG_RDX;
        case ZYDIS_REGISTER_RBX: case ZYDIS_REGISTER_EBX: case ZYDIS_REGISTER_BX:
        case ZYDIS_REGISTER_BL:  case ZYDIS_REGISTER_BH:  return VREG_RBX;
        case ZYDIS_REGISTER_RSP: case ZYDIS_REGISTER_ESP: return VREG_RSP;
        case ZYDIS_REGISTER_RBP: case ZYDIS_REGISTER_EBP: return VREG_RBP;
        case ZYDIS_REGISTER_RSI: case ZYDIS_REGISTER_ESI: return VREG_RSI;
        case ZYDIS_REGISTER_RDI: case ZYDIS_REGISTER_EDI: return VREG_RDI;
        case ZYDIS_REGISTER_R8:  case ZYDIS_REGISTER_R8D: return VREG_R8;
        case ZYDIS_REGISTER_R9:  case ZYDIS_REGISTER_R9D: return VREG_R9;
        default: return VREG_SCRATCH0;
        }
    }

    struct native_exit_t
    {
        uint64_t addr;
        uint32_t length;
    };

    struct lifted_result_t
    {
        std::vector<uint8_t> bytecode;
        std::vector<native_exit_t> native_exits;
        uint32_t total_lifted;
        uint32_t total_native;
    };

    inline bool is_liftable(const ZydisDecodedInstruction& instr,
                            const ZydisDecodedOperand* ops)
    {
        switch (instr.mnemonic) {
        case ZYDIS_MNEMONIC_MOV:
        case ZYDIS_MNEMONIC_ADD:
        case ZYDIS_MNEMONIC_SUB:
        case ZYDIS_MNEMONIC_XOR:
        case ZYDIS_MNEMONIC_AND:
        case ZYDIS_MNEMONIC_OR:
        case ZYDIS_MNEMONIC_NOT:
        case ZYDIS_MNEMONIC_NEG:
        case ZYDIS_MNEMONIC_SHL:
        case ZYDIS_MNEMONIC_SHR:
        case ZYDIS_MNEMONIC_ROL:
        case ZYDIS_MNEMONIC_ROR:
        case ZYDIS_MNEMONIC_CMP:
        case ZYDIS_MNEMONIC_TEST:
        case ZYDIS_MNEMONIC_PUSH:
        case ZYDIS_MNEMONIC_POP:
        case ZYDIS_MNEMONIC_NOP:
        case ZYDIS_MNEMONIC_LEA:
        case ZYDIS_MNEMONIC_INC:
        case ZYDIS_MNEMONIC_DEC:
        case ZYDIS_MNEMONIC_IMUL:
        case ZYDIS_MNEMONIC_MUL:
        case ZYDIS_MNEMONIC_CALL:
        case ZYDIS_MNEMONIC_JB:
        case ZYDIS_MNEMONIC_JBE:
        case ZYDIS_MNEMONIC_JL:
        case ZYDIS_MNEMONIC_JLE:
        case ZYDIS_MNEMONIC_JNB:
        case ZYDIS_MNEMONIC_JNBE:
        case ZYDIS_MNEMONIC_JNL:
        case ZYDIS_MNEMONIC_JNLE:
        case ZYDIS_MNEMONIC_JNZ:
        case ZYDIS_MNEMONIC_JZ:
        case ZYDIS_MNEMONIC_JMP:
        case ZYDIS_MNEMONIC_RET:
            return true;
        default:
            return false;
        }
    }

    inline bool is_branch_mnemonic(ZydisMnemonic m)
    {
        return m == ZYDIS_MNEMONIC_JB  || m == ZYDIS_MNEMONIC_JBE ||
               m == ZYDIS_MNEMONIC_JL  || m == ZYDIS_MNEMONIC_JLE ||
               m == ZYDIS_MNEMONIC_JNB || m == ZYDIS_MNEMONIC_JNBE ||
               m == ZYDIS_MNEMONIC_JNL || m == ZYDIS_MNEMONIC_JNLE ||
               m == ZYDIS_MNEMONIC_JNZ || m == ZYDIS_MNEMONIC_JZ ||
               m == ZYDIS_MNEMONIC_JMP;
    }

    inline void lift_reg_reg(program_t& prog, ZydisMnemonic m,
                             uint8_t dst_vreg, uint8_t src_vreg)
    {
        switch (m) {
        case ZYDIS_MNEMONIC_MOV:
            prog.emit_load_reg(dst_vreg, src_vreg);
            break;
        case ZYDIS_MNEMONIC_ADD:
            prog.emit_add(dst_vreg, dst_vreg, src_vreg);
            break;
        case ZYDIS_MNEMONIC_SUB:
            prog.emit_sub(dst_vreg, dst_vreg, src_vreg);
            break;
        case ZYDIS_MNEMONIC_XOR:
            prog.emit_xor(dst_vreg, dst_vreg, src_vreg);
            break;
        case ZYDIS_MNEMONIC_AND:
            prog.emit_nand(dst_vreg, dst_vreg, src_vreg);
            prog.emit_not(dst_vreg, dst_vreg);
            break;
        case ZYDIS_MNEMONIC_OR:
            prog.emit_nor(dst_vreg, dst_vreg, src_vreg);
            prog.emit_not(dst_vreg, dst_vreg);
            break;
        case ZYDIS_MNEMONIC_CMP:
            prog.emit_cmp(dst_vreg, src_vreg);
            break;
        case ZYDIS_MNEMONIC_TEST:
            prog.emit_nand(VREG_SCRATCH2, dst_vreg, src_vreg);
            prog.emit_not(VREG_SCRATCH2, VREG_SCRATCH2);
            prog.emit_load_imm(VREG_SCRATCH3, 0);
            prog.emit_cmp(VREG_SCRATCH2, VREG_SCRATCH3);
            break;
        default:
            break;
        }
    }

    inline void lift_reg_imm(program_t& prog, ZydisMnemonic m,
                             uint8_t dst_vreg, uint64_t imm)
    {
        prog.emit_load_imm(VREG_SCRATCH0, imm);
        lift_reg_reg(prog, m, dst_vreg, VREG_SCRATCH0);
    }

    inline lifted_result_t compile_function(const uint8_t* code, size_t code_len,
                                            uint64_t base_addr, uint64_t initial_key,
                                            const uint8_t opcode_map[256])
    {
        lifted_result_t result{};
        result.total_lifted = 0;
        result.total_native = 0;

        program_t prog;
        prog.set_key(initial_key);
        prog.set_opcode_map(opcode_map);

        ZydisDecoder decoder;
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

        struct instr_info_t {
            ZydisDecodedInstruction instr;
            ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];
            uint64_t                addr;
            uint8_t                 raw[16];
            uint8_t                 length;
        };

        std::vector<instr_info_t> decoded;
        uint64_t offset = 0;

        while (offset < code_len) {
            instr_info_t info{};
            info.addr = base_addr + offset;
            auto status = ZydisDecoderDecodeFull(
                &decoder, code + offset, code_len - offset,
                &info.instr, info.ops);
            if (!ZYAN_SUCCESS(status)) break;
            info.length = static_cast<uint8_t>(info.instr.length);
            memcpy(info.raw, code + offset, info.length);
            decoded.push_back(info);
            offset += info.length;

            if (info.instr.mnemonic == ZYDIS_MNEMONIC_RET ||
                info.instr.mnemonic == ZYDIS_MNEMONIC_INT3)
                break;
        }

        std::unordered_map<uint64_t, uint32_t> addr_to_label;
        for (auto& di : decoded) {
            if (is_branch_mnemonic(di.instr.mnemonic)) {
                for (int i = 0; i < di.instr.operand_count; ++i) {
                    if (di.ops[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                        uint64_t target = di.addr + di.length;
                        if (di.ops[i].imm.is_relative)
                            target += di.ops[i].imm.value.s;
                        else
                            target = di.ops[i].imm.value.u;

                        if (addr_to_label.find(target) == addr_to_label.end())
                            addr_to_label[target] = prog.create_label();
                    }
                }
            }
        }

        prog.emit_vm_enter();
        prog.emit_junk(2);

        for (size_t idx = 0; idx < decoded.size(); ++idx) {
            auto& di = decoded[idx];

            auto lbl_it = addr_to_label.find(di.addr);
            if (lbl_it != addr_to_label.end())
                prog.bind_label(lbl_it->second);

            if (!is_liftable(di.instr, di.ops)) {
                native_exit_t ne;
                ne.addr = di.addr;
                ne.length = di.length;
                result.native_exits.push_back(ne);
                result.total_native++;

                prog.emit_vm_exit();
                prog.emit_load_imm(VREG_SCRATCH2, di.addr);
                prog.emit_vm_enter();
                prog.emit_junk(1);
                continue;
            }

            result.total_lifted++;

            if (di.instr.mnemonic == ZYDIS_MNEMONIC_NOP) {
                prog.emit_nop();
                continue;
            }

            if (di.instr.mnemonic == ZYDIS_MNEMONIC_RET) {
                prog.emit_vret();
                continue;
            }

            if (di.instr.mnemonic == ZYDIS_MNEMONIC_CALL) {
                if (di.ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    uint64_t target = di.addr + di.length;
                    if (di.ops[0].imm.is_relative)
                        target += di.ops[0].imm.value.s;
                    else
                        target = di.ops[0].imm.value.u;
                    auto tgt_it = addr_to_label.find(target);
                    if (tgt_it != addr_to_label.end()) {
                        prog.emit_vcall_label(tgt_it->second);
                        result.total_lifted++;
                        continue;
                    }
                }
                prog.emit_vm_exit();
                prog.emit_load_imm(VREG_SCRATCH2, di.addr);
                prog.emit_vm_enter();
                result.total_native++;
                continue;
            }

            if (di.instr.mnemonic == ZYDIS_MNEMONIC_MUL) {
                if (di.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    uint8_t src = zydis_reg_to_vreg(di.ops[0].reg.value);
                    prog.emit_mul(VREG_RAX, src);
                }
                continue;
            }

            if (di.instr.mnemonic == ZYDIS_MNEMONIC_IMUL) {
                if (di.instr.operand_count >= 2 &&
                    di.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    di.ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    uint8_t dst = zydis_reg_to_vreg(di.ops[0].reg.value);
                    uint8_t src = zydis_reg_to_vreg(di.ops[1].reg.value);
                    prog.emit_imul(dst, src);
                } else if (di.instr.operand_count >= 3 &&
                    di.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    di.ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    di.ops[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    uint8_t dst = zydis_reg_to_vreg(di.ops[0].reg.value);
                    uint8_t src = zydis_reg_to_vreg(di.ops[1].reg.value);
                    prog.emit_load_imm(VREG_SCRATCH0, di.ops[2].imm.value.u);
                    prog.emit_load_reg(dst, src);
                    prog.emit_imul(dst, VREG_SCRATCH0);
                } else if (di.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    uint8_t src = zydis_reg_to_vreg(di.ops[0].reg.value);
                    prog.emit_imul(VREG_RAX, src);
                }
                continue;
            }

            if (is_branch_mnemonic(di.instr.mnemonic)) {
                uint64_t target = di.addr + di.length;
                for (int i = 0; i < di.instr.operand_count; ++i) {
                    if (di.ops[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                        if (di.ops[i].imm.is_relative)
                            target = di.addr + di.length + di.ops[i].imm.value.s;
                        else
                            target = di.ops[i].imm.value.u;
                        break;
                    }
                }

                auto tgt_it = addr_to_label.find(target);
                if (tgt_it == addr_to_label.end()) {
                    prog.emit_vm_exit();
                    prog.emit_load_imm(VREG_SCRATCH2, target);
                    result.total_native++;
                    continue;
                }

                if (di.instr.mnemonic == ZYDIS_MNEMONIC_JMP) {
                    prog.emit_jmp_label(tgt_it->second);
                } else if (di.instr.mnemonic == ZYDIS_MNEMONIC_JZ) {
                    prog.emit_jz_label(tgt_it->second);
                } else if (di.instr.mnemonic == ZYDIS_MNEMONIC_JNZ) {
                    prog.emit_jnz_label(tgt_it->second);
                } else if (di.instr.mnemonic == ZYDIS_MNEMONIC_JL) {
                    prog.emit_jl_label(tgt_it->second);
                } else if (di.instr.mnemonic == ZYDIS_MNEMONIC_JLE) {
                    prog.emit_jle_label(tgt_it->second);
                } else if (di.instr.mnemonic == ZYDIS_MNEMONIC_JNL) {
                    prog.emit_jge_label(tgt_it->second);
                } else if (di.instr.mnemonic == ZYDIS_MNEMONIC_JNLE) {
                    prog.emit_jg_label(tgt_it->second);
                } else if (di.instr.mnemonic == ZYDIS_MNEMONIC_JB) {
                    prog.emit_jb_label(tgt_it->second);
                } else if (di.instr.mnemonic == ZYDIS_MNEMONIC_JBE) {
                    prog.emit_jbe_label(tgt_it->second);
                } else if (di.instr.mnemonic == ZYDIS_MNEMONIC_JNB) {
                    prog.emit_jnb_label(tgt_it->second);
                } else if (di.instr.mnemonic == ZYDIS_MNEMONIC_JNBE) {
                    prog.emit_jnbe_label(tgt_it->second);
                } else {
                    prog.emit_vm_exit();
                    prog.emit_load_imm(VREG_SCRATCH2, target);
                    result.total_native++;
                }
                continue;
            }

            if (di.instr.mnemonic == ZYDIS_MNEMONIC_PUSH) {
                if (di.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    prog.emit_push(zydis_reg_to_vreg(di.ops[0].reg.value));
                } else if (di.ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    prog.emit_load_imm(VREG_SCRATCH0, di.ops[0].imm.value.u);
                    prog.emit_push(VREG_SCRATCH0);
                }
                continue;
            }

            if (di.instr.mnemonic == ZYDIS_MNEMONIC_POP) {
                if (di.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    prog.emit_pop(zydis_reg_to_vreg(di.ops[0].reg.value));
                }
                continue;
            }

            if (di.instr.mnemonic == ZYDIS_MNEMONIC_NOT) {
                if (di.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    uint8_t r = zydis_reg_to_vreg(di.ops[0].reg.value);
                    prog.emit_not(r, r);
                }
                continue;
            }

            if (di.instr.mnemonic == ZYDIS_MNEMONIC_NEG) {
                if (di.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    uint8_t r = zydis_reg_to_vreg(di.ops[0].reg.value);
                    prog.emit_not(r, r);
                    prog.emit_load_imm(VREG_SCRATCH0, 1);
                    prog.emit_add(r, r, VREG_SCRATCH0);
                }
                continue;
            }

            if (di.instr.mnemonic == ZYDIS_MNEMONIC_INC) {
                if (di.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    uint8_t r = zydis_reg_to_vreg(di.ops[0].reg.value);
                    prog.emit_load_imm(VREG_SCRATCH0, 1);
                    prog.emit_add(r, r, VREG_SCRATCH0);
                }
                continue;
            }

            if (di.instr.mnemonic == ZYDIS_MNEMONIC_DEC) {
                if (di.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    uint8_t r = zydis_reg_to_vreg(di.ops[0].reg.value);
                    prog.emit_load_imm(VREG_SCRATCH0, 1);
                    prog.emit_sub(r, r, VREG_SCRATCH0);
                }
                continue;
            }

            if (di.instr.mnemonic == ZYDIS_MNEMONIC_LEA) {
                if (di.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    di.ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    uint8_t dst = zydis_reg_to_vreg(di.ops[0].reg.value);
                    if (di.ops[1].mem.base == ZYDIS_REGISTER_RIP) {
                        uint64_t lea_target = di.addr + di.length +
                            static_cast<int64_t>(di.ops[1].mem.disp.value);
                        prog.emit_load_imm(dst, lea_target);
                    } else {
                        uint8_t base_reg = zydis_reg_to_vreg(di.ops[1].mem.base);
                        prog.emit_load_reg(dst, base_reg);
                        if (di.ops[1].mem.disp.size > 0 && di.ops[1].mem.disp.value != 0) {
                            int64_t disp = di.ops[1].mem.disp.value;
                            prog.emit_load_imm(VREG_SCRATCH1, static_cast<uint64_t>(disp));
                            prog.emit_add(dst, dst, VREG_SCRATCH1);
                        }
                        if (di.ops[1].mem.index != ZYDIS_REGISTER_NONE) {
                            uint8_t idx_reg = zydis_reg_to_vreg(di.ops[1].mem.index);
                            uint8_t scale = di.ops[1].mem.scale;
                            if (scale > 1) {
                                prog.emit_load_imm(VREG_SCRATCH1, scale);
                                prog.emit_load_reg(VREG_SCRATCH2, idx_reg);
                                uint8_t shift_bits = 0;
                                if (scale == 2) shift_bits = 1;
                                else if (scale == 4) shift_bits = 2;
                                else if (scale == 8) shift_bits = 3;
                                prog.emit_load_imm(VREG_SCRATCH3, shift_bits);
                                prog.emit_shl(VREG_SCRATCH2, VREG_SCRATCH2, VREG_SCRATCH3);
                                prog.emit_add(dst, dst, VREG_SCRATCH2);
                            } else {
                                prog.emit_add(dst, dst, idx_reg);
                            }
                        }
                    }
                }
                continue;
            }

            if (di.instr.mnemonic == ZYDIS_MNEMONIC_SHL ||
                di.instr.mnemonic == ZYDIS_MNEMONIC_SHR ||
                di.instr.mnemonic == ZYDIS_MNEMONIC_ROL ||
                di.instr.mnemonic == ZYDIS_MNEMONIC_ROR) {
                if (di.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    uint8_t dst = zydis_reg_to_vreg(di.ops[0].reg.value);
                    uint8_t amount = VREG_SCRATCH0;
                    if (di.ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                        prog.emit_load_imm(VREG_SCRATCH0, di.ops[1].imm.value.u & 0x3F);
                    } else if (di.ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                        amount = zydis_reg_to_vreg(di.ops[1].reg.value);
                    }
                    switch (di.instr.mnemonic) {
                    case ZYDIS_MNEMONIC_SHL: prog.emit_shl(dst, dst, amount); break;
                    case ZYDIS_MNEMONIC_SHR: prog.emit_shr(dst, dst, amount); break;
                    case ZYDIS_MNEMONIC_ROL: prog.emit_rol(dst, dst, amount); break;
                    case ZYDIS_MNEMONIC_ROR: prog.emit_ror(dst, dst, amount); break;
                    default: break;
                    }
                }
                continue;
            }

            if (di.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                di.ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                lift_reg_reg(prog, di.instr.mnemonic,
                    zydis_reg_to_vreg(di.ops[0].reg.value),
                    zydis_reg_to_vreg(di.ops[1].reg.value));
                continue;
            }

            if (di.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                di.ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                lift_reg_imm(prog, di.instr.mnemonic,
                    zydis_reg_to_vreg(di.ops[0].reg.value),
                    di.ops[1].imm.value.u);
                continue;
            }

            if (di.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                di.ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                uint8_t dst = zydis_reg_to_vreg(di.ops[0].reg.value);
                if (di.ops[1].mem.base == ZYDIS_REGISTER_RIP) {
                    uint64_t mem_addr = di.addr + di.length +
                        static_cast<int64_t>(di.ops[1].mem.disp.value);
                    prog.emit_load_imm(VREG_SCRATCH0, mem_addr);
                } else {
                    uint8_t base_reg = zydis_reg_to_vreg(di.ops[1].mem.base);
                    prog.emit_load_reg(VREG_SCRATCH0, base_reg);
                    if (di.ops[1].mem.disp.size > 0 && di.ops[1].mem.disp.value != 0) {
                        prog.emit_load_imm(VREG_SCRATCH1, static_cast<uint64_t>(di.ops[1].mem.disp.value));
                        prog.emit_add(VREG_SCRATCH0, VREG_SCRATCH0, VREG_SCRATCH1);
                    }
                }
                if (di.instr.mnemonic == ZYDIS_MNEMONIC_MOV) {
                    prog.emit_load_mem(dst, VREG_SCRATCH0);
                } else {
                    prog.emit_load_mem(VREG_SCRATCH1, VREG_SCRATCH0);
                    lift_reg_reg(prog, di.instr.mnemonic, dst, VREG_SCRATCH1);
                }
                continue;
            }

            if (di.ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                di.ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                uint8_t src = zydis_reg_to_vreg(di.ops[1].reg.value);
                if (di.ops[0].mem.base == ZYDIS_REGISTER_RIP) {
                    uint64_t mem_addr = di.addr + di.length +
                        static_cast<int64_t>(di.ops[0].mem.disp.value);
                    prog.emit_load_imm(VREG_SCRATCH0, mem_addr);
                } else {
                    uint8_t base_reg = zydis_reg_to_vreg(di.ops[0].mem.base);
                    prog.emit_load_reg(VREG_SCRATCH0, base_reg);
                    if (di.ops[0].mem.disp.size > 0 && di.ops[0].mem.disp.value != 0) {
                        prog.emit_load_imm(VREG_SCRATCH1, static_cast<uint64_t>(di.ops[0].mem.disp.value));
                        prog.emit_add(VREG_SCRATCH0, VREG_SCRATCH0, VREG_SCRATCH1);
                    }
                }
                if (di.instr.mnemonic == ZYDIS_MNEMONIC_MOV) {
                    prog.emit_store_mem(VREG_SCRATCH0, src);
                } else {
                    prog.emit_load_mem(VREG_SCRATCH1, VREG_SCRATCH0);
                    lift_reg_reg(prog, di.instr.mnemonic, VREG_SCRATCH1, src);
                    prog.emit_store_mem(VREG_SCRATCH0, VREG_SCRATCH1);
                }
                continue;
            }

            native_exit_t ne;
            ne.addr = di.addr;
            ne.length = di.length;
            result.native_exits.push_back(ne);
            result.total_native++;
            prog.emit_vm_exit();
            prog.emit_load_imm(VREG_SCRATCH2, di.addr);
            prog.emit_vm_enter();
        }

        if (decoded.empty() || decoded.back().instr.mnemonic != ZYDIS_MNEMONIC_RET) {
            prog.emit_vm_exit();
            prog.emit_halt();
        }

        prog.emit_junk(3);
        result.bytecode = prog.finalize();
        return result;
    }

    inline lifted_result_t compile_basic_block(const uint8_t* code, size_t length,
                                               uint64_t base_addr, uint64_t seed,
                                               const uint8_t opcode_map[256])
    {
        lifted_result_t result = compile_function(code, length, base_addr, seed, opcode_map);
        return result;
    }

}
#endif

}
}
