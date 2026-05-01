#pragma once

#include <windows.h>
#include <intrin.h>

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
    inline constexpr uint8_t MIN_NEST_DEPTH = 1;
    inline constexpr uint8_t MAX_NEST_DEPTH = 4;
    inline constexpr uint32_t POW_DIFFICULTY_BITS_BASE = 12;
    inline constexpr uint32_t POW_DIFFICULTY_BITS_MAX = 18;
    inline constexpr uint32_t POW_MAX_ITERATIONS = 1u << 22;

    inline constexpr uint8_t OUTER_VM_CHILD_POOL_ID = 0;

    inline constexpr uint8_t VREG_RESULT         = 0;
    inline constexpr uint8_t VREG_INNER_RVA_LO   = 1;
    inline constexpr uint8_t VREG_INNER_RVA_HI   = 2;
    inline constexpr uint8_t VREG_INNER_KEY      = 3;
    inline constexpr uint8_t VREG_INNER_LEN      = 4;
    inline constexpr uint8_t VREG_INNER_OFFSET   = 5;
    inline constexpr uint8_t VREG_POW_NONCE      = 6;
    inline constexpr uint8_t VREG_POW_TARGET     = 7;
    inline constexpr uint8_t VREG_SCRATCH_A      = 10;
    inline constexpr uint8_t VREG_SCRATCH_B      = 11;

    struct level_descriptor_t
    {
        std::array<uint8_t, 256> opcode_map;
        std::array<uint8_t, 256> reverse_map;
        uint64_t                 rolling_key;
        uint64_t                 pow_solution;
        uint32_t                 pow_difficulty_bits;
        uint32_t                 isa_seed_lo;
        uint32_t                 isa_seed_hi;
    };

    struct wrap_result_t
    {
        std::vector<uint8_t>            outer_bytecode;
        std::vector<level_descriptor_t> levels;
        uint8_t                         nest_depth;
        uint8_t                         criticality_score;
        uint32_t                        outer_rva;
        bool                            ok;
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

        inline uint8_t derive_nest_depth(uint8_t criticality_score)
        {
            uint32_t bucket = static_cast<uint32_t>(criticality_score) >> 6;
            uint8_t depth = static_cast<uint8_t>(MIN_NEST_DEPTH + bucket);
            if (depth < MIN_NEST_DEPTH) depth = MIN_NEST_DEPTH;
            if (depth > MAX_NEST_DEPTH) depth = MAX_NEST_DEPTH;
            return depth;
        }

        inline uint32_t derive_pow_difficulty(uint8_t criticality_score, uint8_t level_index)
        {
            uint32_t bits = POW_DIFFICULTY_BITS_BASE
                          + (static_cast<uint32_t>(criticality_score) >> 5)
                          + static_cast<uint32_t>(level_index);
            if (bits > POW_DIFFICULTY_BITS_MAX) bits = POW_DIFFICULTY_BITS_MAX;
            return bits;
        }

        inline void derive_level_isa(uint8_t level_index,
                                     uint8_t criticality_score,
                                     uint32_t outer_rva,
                                     uint64_t inner_rolling_key,
                                     const uint8_t master_key[32],
                                     std::array<uint8_t, 256>& out_map,
                                     std::array<uint8_t, 256>& out_reverse,
                                     uint64_t& out_rolling_key)
        {
            uint8_t info[32];
            memcpy(info, "aida_vmnest_isa_v1|level=", 25);
            info[25] = level_index;
            info[26] = criticality_score;
            memcpy(info + 27, &outer_rva, 4);
            info[31] = static_cast<uint8_t>((outer_rva >> 31) & 0xFF);

            uint8_t ikm[24];
            memcpy(ikm, &inner_rolling_key, 8);
            uint64_t mix = static_cast<uint64_t>(level_index) * 0x9E3779B97F4A7C15ULL
                         ^ static_cast<uint64_t>(outer_rva);
            memcpy(ikm + 8, &mix, 8);
            memcpy(ikm + 16, &inner_rolling_key, 8);

            uint8_t prk[32];
            virtualizer::detail::hmac_sha256(master_key, 32, ikm, 24, prk);

            uint8_t okm[296];
            virtualizer::detail::hkdf_expand_sha256(prk, info, 32, okm, 296);

            for (int i = 0; i < 256; ++i) out_map[i] = static_cast<uint8_t>(i);
            for (int i = 255; i > 0; --i)
            {
                uint32_t j = static_cast<uint32_t>(okm[i]) % static_cast<uint32_t>(i + 1);
                uint8_t tmp = out_map[i];
                out_map[i] = out_map[j];
                out_map[j] = tmp;
            }
            for (int i = 0; i < 256; ++i) out_reverse[out_map[i]] = static_cast<uint8_t>(i);

            uint64_t rk = 0;
            memcpy(&rk, okm + 256, 8);
            uint64_t rk2 = 0;
            memcpy(&rk2, okm + 264, 8);
            out_rolling_key = rk ^ _rotl64(rk2, 23);

            SecureZeroMemory(prk, 32);
            SecureZeroMemory(okm, 296);
            SecureZeroMemory(ikm, 24);
            SecureZeroMemory(info, 32);
        }

        inline uint64_t solve_pow(uint8_t level_index,
                                  uint64_t inner_rolling_key,
                                  uint64_t outer_rolling_key,
                                  uint32_t difficulty_bits,
                                  const uint8_t master_key[32])
        {
            uint64_t target_mask;
            if (difficulty_bits >= 64)
                target_mask = 0xFFFFFFFFFFFFFFFFULL;
            else
                target_mask = (1ULL << difficulty_bits) - 1ULL;

            uint8_t pow_key_input[40];
            memcpy(pow_key_input, "aida_vmnest_pow_v1", 18);
            pow_key_input[18] = level_index;
            pow_key_input[19] = static_cast<uint8_t>(difficulty_bits & 0xFF);
            memcpy(pow_key_input + 20, &inner_rolling_key, 8);
            memcpy(pow_key_input + 28, &outer_rolling_key, 8);
            memcpy(pow_key_input + 36, &difficulty_bits, 4);

            uint8_t pow_key[32];
            virtualizer::detail::hmac_sha256(master_key, 32, pow_key_input, 40, pow_key);

            uint64_t nonce = 0;
            for (uint32_t i = 0; i < POW_MAX_ITERATIONS; ++i)
            {
                uint8_t input[8];
                memcpy(input, &nonce, 8);
                uint8_t mac[32];
                virtualizer::detail::hmac_sha256(pow_key, 32, input, 8, mac);
                uint64_t v;
                memcpy(&v, mac, 8);
                if ((v & target_mask) == 0)
                {
                    SecureZeroMemory(pow_key, 32);
                    SecureZeroMemory(pow_key_input, 40);
                    return nonce;
                }
                ++nonce;
            }

            SecureZeroMemory(pow_key, 32);
            SecureZeroMemory(pow_key_input, 40);
            return 0;
        }

        inline bool verify_pow(uint8_t level_index,
                               uint64_t inner_rolling_key,
                               uint64_t outer_rolling_key,
                               uint32_t difficulty_bits,
                               uint64_t solution,
                               const uint8_t master_key[32])
        {
            uint64_t target_mask;
            if (difficulty_bits >= 64)
                target_mask = 0xFFFFFFFFFFFFFFFFULL;
            else
                target_mask = (1ULL << difficulty_bits) - 1ULL;

            uint8_t pow_key_input[40];
            memcpy(pow_key_input, "aida_vmnest_pow_v1", 18);
            pow_key_input[18] = level_index;
            pow_key_input[19] = static_cast<uint8_t>(difficulty_bits & 0xFF);
            memcpy(pow_key_input + 20, &inner_rolling_key, 8);
            memcpy(pow_key_input + 28, &outer_rolling_key, 8);
            memcpy(pow_key_input + 36, &difficulty_bits, 4);

            uint8_t pow_key[32];
            virtualizer::detail::hmac_sha256(master_key, 32, pow_key_input, 40, pow_key);

            uint8_t input[8];
            memcpy(input, &solution, 8);
            uint8_t mac[32];
            virtualizer::detail::hmac_sha256(pow_key, 32, input, 8, mac);
            uint64_t v;
            memcpy(&v, mac, 8);

            SecureZeroMemory(pow_key, 32);
            SecureZeroMemory(pow_key_input, 40);
            SecureZeroMemory(mac, 32);
            return (v & target_mask) == 0;
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

    inline uint8_t compute_criticality_score(size_t inner_bytecode_size,
                                              uint32_t branches,
                                              uint32_t memory_ops,
                                              bool has_security_calls)
    {
        uint32_t score = 0;
        score += static_cast<uint32_t>((inner_bytecode_size * 64) / MAX_INNER_BYTECODE_BYTES);
        score += branches * 4;
        score += memory_ops * 6;
        if (has_security_calls) score += 64;
        if (score > 255) score = 255;
        return static_cast<uint8_t>(score);
    }

    inline wrap_result_t wrap_critical(const std::vector<uint8_t>& inner_bytecode,
                                       const uint8_t master_key[32],
                                       uint32_t inner_rva,
                                       uint32_t outer_rva,
                                       uint64_t inner_rolling_key,
                                       uint8_t criticality_score)
    {
        wrap_result_t out{};
        out.ok = false;
        out.outer_rva = outer_rva;
        out.criticality_score = criticality_score;

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

        uint8_t depth = detail::derive_nest_depth(criticality_score);
        out.nest_depth = depth;
        out.levels.reserve(depth);

        std::vector<uint8_t> current_payload = inner_bytecode;
        uint64_t current_rolling_key = inner_rolling_key;

        for (uint8_t level = 0; level < depth; ++level)
        {
            level_descriptor_t lvl{};
            lvl.pow_difficulty_bits = detail::derive_pow_difficulty(criticality_score, level);

            detail::derive_level_isa(level, criticality_score, outer_rva,
                                     current_rolling_key, master_key,
                                     lvl.opcode_map, lvl.reverse_map,
                                     lvl.rolling_key);

            lvl.pow_solution = detail::solve_pow(level, current_rolling_key,
                                                 lvl.rolling_key,
                                                 lvl.pow_difficulty_bits,
                                                 master_key);
            if (lvl.pow_solution == 0 && lvl.pow_difficulty_bits > 0)
            {
                detail::set_error("vm_nested: proof-of-work solver exhausted iterations");
                return out;
            }

            uint8_t isa_seed_buf[16];
            memcpy(isa_seed_buf, lvl.opcode_map.data(), 16);
            memcpy(&lvl.isa_seed_lo, isa_seed_buf, 4);
            memcpy(&lvl.isa_seed_hi, isa_seed_buf + 4, 4);

            vm_compiler::program_t prog;
            prog.set_key(lvl.rolling_key);
            prog.set_opcode_map(lvl.opcode_map.data());

            prog.emit_vm_enter();
            prog.emit_junk(2);

            prog.emit_load_imm(VREG_INNER_RVA_LO, static_cast<uint64_t>(inner_rva));
            prog.emit_load_imm(VREG_INNER_RVA_HI, static_cast<uint64_t>(level));
            prog.emit_load_imm(VREG_INNER_KEY, current_rolling_key);
            prog.emit_load_imm(VREG_INNER_LEN, static_cast<uint64_t>(current_payload.size()));
            prog.emit_load_imm(VREG_POW_NONCE, lvl.pow_solution);
            prog.emit_load_imm(VREG_POW_TARGET, static_cast<uint64_t>(lvl.pow_difficulty_bits));

            prog.emit_junk(2);

            prog.emit_load_imm(VREG_SCRATCH_A,
                static_cast<uint64_t>(lvl.isa_seed_lo) |
                (static_cast<uint64_t>(lvl.isa_seed_hi) << 32));
            prog.emit_xor(VREG_SCRATCH_B, VREG_INNER_RVA_LO, VREG_SCRATCH_A);
            prog.emit_hash(VREG_SCRATCH_B, VREG_SCRATCH_B);
            prog.emit_xor(VREG_SCRATCH_B, VREG_SCRATCH_B, VREG_POW_NONCE);
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
                               static_cast<uint32_t>(current_payload.size()),
                               VREG_SCRATCH_B);

            prog.emit_vm_exit();
            prog.emit_halt();

            std::vector<uint8_t> finalized = prog.finalize();
            finalized.insert(finalized.end(),
                             current_payload.begin(), current_payload.end());

            current_payload = std::move(finalized);
            current_rolling_key = lvl.rolling_key;

            out.levels.push_back(std::move(lvl));
        }

        out.outer_bytecode = std::move(current_payload);
        out.ok = true;
        detail::set_error("");
        return out;
    }

    inline wrap_result_t wrap_critical(const std::vector<uint8_t>& inner_bytecode,
                                       const uint8_t master_key[32],
                                       uint32_t inner_rva,
                                       uint32_t outer_rva,
                                       uint64_t inner_rolling_key)
    {
        uint8_t derived_score = compute_criticality_score(inner_bytecode.size(), 0, 0, false);
        return wrap_critical(inner_bytecode, master_key, inner_rva, outer_rva,
                             inner_rolling_key, derived_score);
    }

    inline bool unblock_inner_dispatch(const wrap_result_t& wrapped,
                                       uint8_t level_index,
                                       const uint8_t master_key[32])
    {
        if (!wrapped.ok || level_index >= wrapped.levels.size() || !master_key)
            return false;

        const auto& lvl = wrapped.levels[level_index];
        uint64_t prev_rolling_key = (level_index == 0)
            ? lvl.rolling_key
            : wrapped.levels[level_index - 1].rolling_key;

        uint64_t inner_rk = (level_index == 0)
            ? lvl.rolling_key
            : prev_rolling_key;

        return detail::verify_pow(level_index,
                                   inner_rk,
                                   lvl.rolling_key,
                                   lvl.pow_difficulty_bits,
                                   lvl.pow_solution,
                                   master_key);
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

        for (uint8_t lvl = 0; lvl < wrapped.levels.size(); ++lvl)
        {
            if (!unblock_inner_dispatch(wrapped, lvl, master_key))
            {
                detail::set_error("vm_nested: proof-of-work verification failed");
                return 0;
            }
        }

        uint64_t result = virtualizer::detail::vm_execute_with_rva(
            vm,
            wrapped.outer_bytecode.data(),
            static_cast<uint32_t>(wrapped.outer_bytecode.size()),
            wrapped.outer_rva,
            master_key);

        return result;
    }

}
}
