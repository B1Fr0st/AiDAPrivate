#pragma once

#include "arch_decoder.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace aida::analysis {

struct riscv_decoder_profile_t {
    static constexpr std::uint64_t schema_version = 1;
    static constexpr std::uint64_t capstone_api_major = 5;
    static constexpr std::uint64_t capstone_api_minor = 0;
    static constexpr std::uint64_t capstone_version_extra = 9;
    static constexpr std::size_t canonical_byte_count = 40;

    architecture_mode_t mode = architecture_mode_t::unknown;
    endian_t endian = endian_t::little;

    std::array<std::uint8_t, canonical_byte_count> canonical_bytes() const noexcept;

    friend bool operator==(const riscv_decoder_profile_t& lhs,
                           const riscv_decoder_profile_t& rhs) noexcept {
        return lhs.mode == rhs.mode && lhs.endian == rhs.endian;
    }

    friend bool operator!=(const riscv_decoder_profile_t& lhs,
                           const riscv_decoder_profile_t& rhs) noexcept {
        return !(lhs == rhs);
    }
};

workspace_result_t<riscv_decoder_profile_t>
    make_riscv_decoder_profile(architecture_mode_t mode, endian_t endian);

entity_id_t canonical_riscv_decode_claim_id(const address_t& address) noexcept;

workspace_result_t<void> register_riscv_decoder(arch_decoder_registry_t& registry);
workspace_result_t<void> register_riscv_decoder();

}
