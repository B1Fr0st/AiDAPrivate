#pragma once

#include <cstdint>
#include <cstring>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>

#ifdef AIDA_STANDALONE
#include <Zydis/Zydis.h>
#endif

namespace anti_tamper {
namespace cfg_extract {

struct basic_block_t
{
    uint64_t rva_start;
    uint64_t rva_end;
    uint32_t length;
    bool ends_with_jmp;
    bool ends_with_call;
    bool ends_with_ret;
    bool ends_with_jcc;
    bool has_rip_relative;
    bool touches_tls;
};

#ifdef AIDA_STANDALONE

namespace detail {

    inline bool is_unconditional_jmp(ZydisMnemonic m)
    {
        return m == ZYDIS_MNEMONIC_JMP;
    }

    inline bool is_conditional_jmp(ZydisMnemonic m)
    {
        switch (m) {
        case ZYDIS_MNEMONIC_JB:  case ZYDIS_MNEMONIC_JBE:
        case ZYDIS_MNEMONIC_JL:  case ZYDIS_MNEMONIC_JLE:
        case ZYDIS_MNEMONIC_JNB: case ZYDIS_MNEMONIC_JNBE:
        case ZYDIS_MNEMONIC_JNL: case ZYDIS_MNEMONIC_JNLE:
        case ZYDIS_MNEMONIC_JZ:  case ZYDIS_MNEMONIC_JNZ:
        case ZYDIS_MNEMONIC_JS:  case ZYDIS_MNEMONIC_JNS:
        case ZYDIS_MNEMONIC_JO:  case ZYDIS_MNEMONIC_JNO:
        case ZYDIS_MNEMONIC_JP:  case ZYDIS_MNEMONIC_JNP:
        case ZYDIS_MNEMONIC_JCXZ: case ZYDIS_MNEMONIC_JECXZ: case ZYDIS_MNEMONIC_JRCXZ:
        case ZYDIS_MNEMONIC_LOOP: case ZYDIS_MNEMONIC_LOOPE: case ZYDIS_MNEMONIC_LOOPNE:
            return true;
        default:
            return false;
        }
    }

    inline bool is_terminator(ZydisMnemonic m)
    {
        if (is_unconditional_jmp(m) || is_conditional_jmp(m))
            return true;
        switch (m) {
        case ZYDIS_MNEMONIC_RET:
        case ZYDIS_MNEMONIC_INT:
        case ZYDIS_MNEMONIC_INT3:
        case ZYDIS_MNEMONIC_UD2:
        case ZYDIS_MNEMONIC_CALL:
            return true;
        default:
            return false;
        }
    }

    struct decoded_instr_t
    {
        ZydisDecodedInstruction instr;
        ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];
        uint64_t                addr;
        uint8_t                 length;
        bool                    valid;
    };

    inline bool operand_uses_rip(const ZydisDecodedInstruction& instr,
                                 const ZydisDecodedOperand* ops)
    {
        if ((instr.attributes & ZYDIS_ATTRIB_IS_RELATIVE) != 0)
            return true;
        for (int i = 0; i < instr.operand_count; ++i) {
            if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                ops[i].mem.base == ZYDIS_REGISTER_RIP)
                return true;
        }
        return false;
    }

    inline bool operand_uses_gs(const ZydisDecodedInstruction& instr,
                                const ZydisDecodedOperand* ops)
    {
        for (int i = 0; i < instr.operand_count; ++i) {
            if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                ops[i].mem.segment == ZYDIS_REGISTER_GS)
                return true;
        }
        (void)instr;
        return false;
    }
}

inline std::vector<basic_block_t> extract_blocks(
    const void* code, size_t code_size, uint64_t base_addr, size_t max_blocks = 256)
{
    std::vector<basic_block_t> result;
    if (code == nullptr || code_size == 0)
        return result;

    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder,
            ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
        return result;

    const uint8_t* bytes = static_cast<const uint8_t*>(code);

    std::vector<detail::decoded_instr_t> decoded;
    decoded.reserve(256);
    std::unordered_map<uint64_t, size_t> addr_to_idx;

    size_t offset = 0;
    while (offset < code_size) {
        detail::decoded_instr_t di{};
        di.addr = base_addr + offset;
        auto status = ZydisDecoderDecodeFull(
            &decoder, bytes + offset, code_size - offset,
            &di.instr, di.ops);
        if (!ZYAN_SUCCESS(status)) {
            offset += 1;
            continue;
        }
        di.length = static_cast<uint8_t>(di.instr.length);
        di.valid = true;
        addr_to_idx[di.addr] = decoded.size();
        decoded.push_back(di);
        offset += di.length;
    }

    if (decoded.empty())
        return result;

    std::unordered_set<uint64_t> leaders;
    leaders.insert(decoded[0].addr);

    for (const auto& di : decoded) {
        if (detail::is_unconditional_jmp(di.instr.mnemonic) ||
            detail::is_conditional_jmp(di.instr.mnemonic)) {
            for (int i = 0; i < di.instr.operand_count; ++i) {
                if (di.ops[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                    di.ops[i].imm.is_relative) {
                    uint64_t target = di.addr + di.length +
                        static_cast<int64_t>(di.ops[i].imm.value.s);
                    if (target >= base_addr && target < base_addr + code_size)
                        leaders.insert(target);
                }
            }
        }
        if (detail::is_terminator(di.instr.mnemonic)) {
            uint64_t fall = di.addr + di.length;
            if (fall >= base_addr && fall < base_addr + code_size)
                leaders.insert(fall);
        }
    }

    std::vector<uint64_t> sorted_leaders(leaders.begin(), leaders.end());
    std::sort(sorted_leaders.begin(), sorted_leaders.end());

    std::unordered_set<uint64_t> leader_set(sorted_leaders.begin(), sorted_leaders.end());

    for (uint64_t leader_addr : sorted_leaders) {
        if (result.size() >= max_blocks) break;

        auto it = addr_to_idx.find(leader_addr);
        if (it == addr_to_idx.end()) continue;

        size_t idx = it->second;
        basic_block_t block{};
        block.rva_start = leader_addr;
        block.ends_with_jmp = false;
        block.ends_with_call = false;
        block.ends_with_ret = false;
        block.ends_with_jcc = false;
        block.has_rip_relative = false;
        block.touches_tls = false;

        uint64_t cur = leader_addr;
        bool terminated = false;

        while (idx < decoded.size()) {
            const auto& di = decoded[idx];
            if (di.addr != cur) break;

            if (detail::operand_uses_rip(di.instr, di.ops))
                block.has_rip_relative = true;
            if (detail::operand_uses_gs(di.instr, di.ops))
                block.touches_tls = true;

            uint64_t next_addr = di.addr + di.length;

            if (detail::is_terminator(di.instr.mnemonic)) {
                if (detail::is_unconditional_jmp(di.instr.mnemonic))
                    block.ends_with_jmp = true;
                else if (detail::is_conditional_jmp(di.instr.mnemonic))
                    block.ends_with_jcc = true;
                else if (di.instr.mnemonic == ZYDIS_MNEMONIC_CALL)
                    block.ends_with_call = true;
                else if (di.instr.mnemonic == ZYDIS_MNEMONIC_RET)
                    block.ends_with_ret = true;
                cur = next_addr;
                terminated = true;
                break;
            }

            if (next_addr != leader_addr &&
                leader_set.find(next_addr) != leader_set.end() &&
                next_addr != cur + di.length) {
                cur = next_addr;
                terminated = true;
                break;
            }

            cur = next_addr;
            ++idx;

            if (leader_set.find(cur) != leader_set.end() && cur != leader_addr) {
                terminated = true;
                break;
            }
        }

        block.rva_end = cur;
        if (block.rva_end <= block.rva_start) continue;
        uint64_t len64 = block.rva_end - block.rva_start;
        if (len64 > 0xFFFFFFFFULL) continue;
        block.length = static_cast<uint32_t>(len64);

        (void)terminated;
        result.push_back(block);
    }

    return result;
}

#else

inline std::vector<basic_block_t> extract_blocks(
    const void* code, size_t code_size, uint64_t base_addr, size_t max_blocks = 256)
{
    (void)code; (void)code_size; (void)base_addr; (void)max_blocks;
    return {};
}

#endif

}
}
