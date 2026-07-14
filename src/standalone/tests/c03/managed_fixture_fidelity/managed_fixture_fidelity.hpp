#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace aida::analysis::c03
{
    struct managed_fixture_dex_layout_t
    {
        std::uint32_t file_size = 0;
        std::uint32_t data_offset = 0;
        std::uint32_t map_offset = 0;
        std::uint32_t string_count = 0;
        std::uint32_t type_count = 0;
        std::uint32_t proto_count = 0;
        std::uint32_t method_count = 0;
        std::uint32_t class_count = 0;
        std::uint32_t string_data_offset = 0;
        std::uint32_t debug_info_offset = 0;
        std::uint32_t code_item_offset = 0;
        std::uint32_t class_data_offset = 0;
        std::uint32_t code_item_count = 0;
        std::uint32_t debug_info_count = 0;
    };

    struct managed_fixture_fidelity_result_t
    {
        bool valid = false;
        std::string error;
        managed_fixture_dex_layout_t dex;
    };

    std::array<std::uint8_t, 20> c03_dex_sha1(
        const std::vector<std::uint8_t>& bytes, std::size_t offset);
    std::uint32_t c03_dex_adler32(
        const std::vector<std::uint8_t>& bytes, std::size_t offset) noexcept;
    bool seal_c03_dex(std::vector<std::uint8_t>& bytes, std::string& error);
    managed_fixture_fidelity_result_t validate_c03_dex_fidelity(
        const std::vector<std::uint8_t>& bytes);
    bool extract_c03_stored_zip_member(const std::vector<std::uint8_t>& archive,
        std::string_view expected_name, std::vector<std::uint8_t>& member,
        std::string& error);
}
