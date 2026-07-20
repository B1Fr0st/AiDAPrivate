#pragma once

#include "arch_decoder.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace aida::analysis {

enum class mips_mode_t : std::uint8_t {
    mips32 = 0,
    mips64 = 1
};

struct mips_decoder_profile_t {
    static constexpr std::uint64_t schema_version = 4;
    static constexpr std::uint64_t capstone_api_major = 5;
    static constexpr std::uint64_t capstone_api_minor = 0;
    static constexpr std::uint64_t capstone_version_extra = 9;
    static constexpr std::size_t canonical_byte_count = 64;

    mips_mode_t mode = mips_mode_t::mips32;
    endian_t endian = endian_t::little;
    bool micromips = false;

    std::array<std::uint8_t, canonical_byte_count> canonical_bytes() const noexcept;

    friend bool operator==(const mips_decoder_profile_t& lhs,
                           const mips_decoder_profile_t& rhs) noexcept {
        return lhs.mode == rhs.mode && lhs.endian == rhs.endian &&
               lhs.micromips == rhs.micromips;
    }

    friend bool operator!=(const mips_decoder_profile_t& lhs,
                           const mips_decoder_profile_t& rhs) noexcept {
        return !(lhs == rhs);
    }
};

workspace_result_t<mips_decoder_profile_t>
make_mips_decoder_profile(mips_mode_t mode, endian_t endian, bool micromips = false);

workspace_result_t<arch_decoder_key_t>
make_mips_decoder_key(mips_mode_t mode, endian_t endian,
                      abi_id_t abi = abi_id_t::unknown);

workspace_result_t<void> register_mips_decoder(arch_decoder_registry_t& registry);
workspace_result_t<void> register_default_mips_decoder();

}
