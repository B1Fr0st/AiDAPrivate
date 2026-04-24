#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "virtualizer.hpp"
#include "vm_compiler.hpp"

namespace anti_tamper {
namespace vm_nested {

    inline constexpr size_t MAX_INNER_BYTECODE_BYTES = 4096;

    inline constexpr uint64_t OUTER_MAP_SALT = 0xA1DA00B1DA7E57EFULL;

    inline constexpr uint64_t OUTER_ROLLING_SEED_MIX = 0x6A09E667F3BCC908ULL;

    inline constexpr uint8_t OUTER_VM_CHILD_POOL_ID = 0;

    inline constexpr uint8_t VREG_RESULT         = 0;
    inline constexpr uint8_t VREG_INNER_RVA_LO   = 1;
    inline constexpr uint8_t VREG_INNER_RVA_HI   = 2;
    inline constexpr uint8_t VREG_INNER_KEY      = 3;
    inline constexpr uint8_t VREG_INNER_LEN      = 4;
    inline constexpr uint8_t VREG_INNER_OFFSET   = 5;
    inline constexpr uint8_t VREG_SCRATCH_A      = 10;
    inline constexpr uint8_t VREG_SCRATCH_B      = 11;

    struct wrap_result_t
    {
        std::vector<uint8_t>     outer_bytecode;
        std::array<uint8_t, 256> outer_opcode_map;
        std::array<uint8_t, 256> outer_reverse_map;
        uint64_t                 outer_rolling_key;
        uint32_t                 outer_rva;
        bool                     ok;
    };

    namespace detail
    {
        inline std::string& error_slot()
        {
            static std::string s_last_error;
            return s_last_error;
        }

        inline void set_error(const char* msg)
        {
            error_slot() = msg ? msg : "";
        }

        inline uint32_t salted_rva(uint32_t outer_rva)
        {
            uint64_t mixed = static_cast<uint64_t>(outer_rva) ^ OUTER_MAP_SALT;
            return static_cast<uint32_t>(mixed & 0xFFFFFFFFULL);
        }

        inline uint64_t derive_outer_rolling_key(uint64_t inner_rolling_key,
                                                 uint32_t inner_rva)
        {
            uint64_t mixed = inner_rolling_key;
            mixed ^= (static_cast<uint64_t>(inner_rva) << 32);
            mixed ^= OUTER_ROLLING_SEED_MIX;
            return mixed;
        }
    }

    inline const char* last_error()
    {
        return detail::error_slot().c_str();
    }

    inline bool is_eligible(size_t inner_bytecode_size)
    {
        return inner_bytecode_size <= MAX_INNER_BYTECODE_BYTES;
    }

    inline wrap_result_t wrap_critical(const std::vector<uint8_t>& inner_bytecode,
                                       const uint8_t master_key[32],
                                       uint32_t inner_rva,
                                       uint32_t outer_rva,
                                       uint64_t inner_rolling_key)
    {
        wrap_result_t out{};
        out.ok = false;
        out.outer_rva = outer_rva;

        if (inner_bytecode.empty())
        {
            detail::set_error("vm_nested: inner_bytecode is empty");
            return out;
        }

        if (inner_bytecode.size() > MAX_INNER_BYTECODE_BYTES)
        {
            detail::set_error("vm_nested: inner_bytecode exceeds MAX_INNER_BYTECODE_BYTES");
            return out;
        }

        if (!master_key)
        {
            detail::set_error("vm_nested: master_key is null");
            return out;
        }

        uint32_t effective_rva = detail::salted_rva(outer_rva);

        std::array<uint8_t, 256> outer_map{};
        std::array<uint8_t, 256> outer_reverse{};
        {
            auto derived = virtualizer::detail::derive_function_opcode_map(
                effective_rva, master_key);
            for (int i = 0; i < 256; ++i)
            {
                outer_map[i] = derived[i];
                outer_reverse[derived[i]] = static_cast<uint8_t>(i);
            }
            SecureZeroMemory(derived.data(), 256);
        }

        uint64_t outer_rolling_key = detail::derive_outer_rolling_key(
            inner_rolling_key, inner_rva);

        vm_compiler::program_t prog;
        prog.set_key(outer_rolling_key);
        prog.set_opcode_map(outer_map.data());

        prog.emit_vm_enter();
        prog.emit_junk(2);

        uint32_t inner_rva_lo = static_cast<uint32_t>(inner_rva);
        uint32_t inner_rva_hi = static_cast<uint32_t>(0);
        prog.emit_load_imm(VREG_INNER_RVA_LO, static_cast<uint64_t>(inner_rva_lo));
        prog.emit_load_imm(VREG_INNER_RVA_HI, static_cast<uint64_t>(inner_rva_hi));
        prog.emit_load_imm(VREG_INNER_KEY, inner_rolling_key);
        prog.emit_load_imm(VREG_INNER_LEN,
            static_cast<uint64_t>(inner_bytecode.size()));

        prog.emit_junk(2);

        prog.emit_load_imm(VREG_SCRATCH_A, OUTER_MAP_SALT);
        prog.emit_xor(VREG_SCRATCH_B, VREG_INNER_RVA_LO, VREG_SCRATCH_A);
        prog.emit_hash(VREG_SCRATCH_B, VREG_SCRATCH_B);

        prog.emit_load_reg(VREG_RESULT, VREG_INNER_RVA_LO);

        uint32_t spawn_start = prog.current_offset();
        uint32_t spawn_size = 11u;
        uint32_t load_offset_size = 10u;
        uint32_t tail_size = 2u;
        uint32_t inner_offset = spawn_start + load_offset_size + spawn_size + tail_size;
        prog.emit_load_imm(VREG_INNER_OFFSET, static_cast<uint64_t>(inner_offset));

        prog.emit_vm_spawn(OUTER_VM_CHILD_POOL_ID,
                           inner_offset,
                           static_cast<uint32_t>(inner_bytecode.size()),
                           VREG_SCRATCH_B);

        prog.emit_vm_exit();
        prog.emit_halt();

        std::vector<uint8_t> finalized = prog.finalize();

        finalized.insert(finalized.end(),
                         inner_bytecode.begin(), inner_bytecode.end());

        out.outer_bytecode = std::move(finalized);
        out.outer_opcode_map = outer_map;
        out.outer_reverse_map = outer_reverse;
        out.outer_rolling_key = outer_rolling_key;
        out.outer_rva = outer_rva;
        out.ok = true;

        SecureZeroMemory(outer_map.data(), 256);
        SecureZeroMemory(outer_reverse.data(), 256);

        detail::set_error("");
        return out;
    }

    inline uint64_t execute_nested(const wrap_result_t& wrapped,
                                   virtualizer::detail::vm_state_t& vm,
                                   const uint8_t master_key[32])
    {
        if (!wrapped.ok || wrapped.outer_bytecode.empty() || !master_key)
        {
            detail::set_error("vm_nested: execute_nested received invalid state");
            return 0;
        }

        uint32_t effective_rva = detail::salted_rva(wrapped.outer_rva);

        uint64_t result = virtualizer::detail::vm_execute_with_rva(
            vm,
            wrapped.outer_bytecode.data(),
            static_cast<uint32_t>(wrapped.outer_bytecode.size()),
            effective_rva,
            master_key);

        return result;
    }

}
}
