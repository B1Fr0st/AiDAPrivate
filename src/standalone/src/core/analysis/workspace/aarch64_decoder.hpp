#pragma once

#include "arch_decoder.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace aida::analysis {

struct aarch64_decoder_profile_t {
    static constexpr std::uint64_t schema_version = 1;
    static constexpr std::uint64_t capstone_api_major = 5;
    static constexpr std::uint64_t capstone_api_minor = 0;
    static constexpr std::uint64_t capstone_version_extra = 9;
    static constexpr std::size_t canonical_byte_count = 40;

    endian_t endian = endian_t::little;

    std::array<std::uint8_t, canonical_byte_count> canonical_bytes() const noexcept;

    friend bool operator==(const aarch64_decoder_profile_t& lhs,
                           const aarch64_decoder_profile_t& rhs) noexcept {
        return lhs.endian == rhs.endian;
    }

    friend bool operator!=(const aarch64_decoder_profile_t& lhs,
                           const aarch64_decoder_profile_t& rhs) noexcept {
        return !(lhs == rhs);
    }
};

workspace_result_t<aarch64_decoder_profile_t>
    make_aarch64_decoder_profile(endian_t endian);

entity_id_t canonical_aarch64_decode_claim_id(const address_t& address) noexcept;

workspace_result_t<void> register_aarch64_decoder(arch_decoder_registry_t& registry);
workspace_result_t<void> register_aarch64_decoder();

}
