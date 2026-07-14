#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace aida::analysis::c03_test {

struct compact_dex_fixture_t final {
    std::vector<std::uint8_t> bytes;
    std::uint32_t main_size = 0;
    std::uint32_t data_size = 0;
    std::uint32_t class_data_offset = 0;
    std::uint32_t code_item_offset = 0;
    std::uint32_t instructions_offset = 0;
    std::uint32_t debug_info_offset = 0;
    std::uint32_t second_debug_info_offset = 0;
    std::uint32_t map_offset = 0;
    std::uint32_t debug_table_position = 0;
};

inline void compact_fixture_require(bool condition, const char* message) {
    if (!condition)
        throw std::runtime_error(message);
}

inline void compact_fixture_write_u16(
    std::vector<std::uint8_t>& bytes,
    std::size_t offset,
    std::uint16_t value) {
    compact_fixture_require(offset + 2 <= bytes.size(),
        "compact fixture u16 write is out of range");
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1] = static_cast<std::uint8_t>(value >> 8U);
}

inline void compact_fixture_write_u32(
    std::vector<std::uint8_t>& bytes,
    std::size_t offset,
    std::uint32_t value) {
    compact_fixture_require(offset + 4 <= bytes.size(),
        "compact fixture u32 write is out of range");
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 2] = static_cast<std::uint8_t>(value >> 16U);
    bytes[offset + 3] = static_cast<std::uint8_t>(value >> 24U);
}

inline compact_dex_fixture_t make_compact_dex_fixture(
    bool extended_register_preheader = true) {
    constexpr std::uint32_t header_size = 136;
    constexpr std::uint32_t string_count = 4;
    constexpr std::uint32_t type_count = 2;
    constexpr std::uint32_t proto_count = 1;
    constexpr std::uint32_t method_count = 2;
    constexpr std::uint32_t class_count = 1;
    constexpr std::uint32_t string_ids_offset = header_size;
    constexpr std::uint32_t type_ids_offset =
        string_ids_offset + string_count * 4U;
    constexpr std::uint32_t proto_ids_offset =
        type_ids_offset + type_count * 4U;
    constexpr std::uint32_t method_ids_offset =
        proto_ids_offset + proto_count * 12U;
    constexpr std::uint32_t class_defs_offset =
        method_ids_offset + method_count * 8U;
    constexpr std::uint32_t main_size =
        class_defs_offset + class_count * 32U;
    constexpr std::uint32_t class_data_offset = 17;
    constexpr std::uint32_t map_offset = 44;
    constexpr std::uint32_t debug_table_position = 180;
    constexpr std::uint32_t debug_table_offset = 4;
    constexpr std::uint32_t data_size = 188;

    compact_dex_fixture_t fixture;
    fixture.main_size = main_size;
    fixture.data_size = data_size;
    fixture.class_data_offset = class_data_offset;
    fixture.code_item_offset = extended_register_preheader ? 32U : 30U;
    fixture.instructions_offset = fixture.code_item_offset + 4U;
    fixture.debug_info_offset = extended_register_preheader ? 38U : 36U;
    fixture.second_debug_info_offset = fixture.debug_info_offset + 3U;
    fixture.map_offset = map_offset;
    fixture.debug_table_position = debug_table_position;
    fixture.bytes.resize(main_size + data_size, 0);
    auto& bytes = fixture.bytes;
    const auto data = static_cast<std::size_t>(main_size);

    bytes[0] = 'c';
    bytes[1] = 'd';
    bytes[2] = 'e';
    bytes[3] = 'x';
    bytes[4] = '0';
    bytes[5] = '0';
    bytes[6] = '1';
    bytes[7] = 0;
    for (std::uint32_t index = 0; index < 20; ++index)
        bytes[12 + index] = static_cast<std::uint8_t>(index + 1U);
    compact_fixture_write_u32(bytes, 32, main_size);
    compact_fixture_write_u32(bytes, 36, header_size);
    compact_fixture_write_u32(bytes, 40, 0x12345678U);
    compact_fixture_write_u32(bytes, 52, map_offset);
    compact_fixture_write_u32(bytes, 56, string_count);
    compact_fixture_write_u32(bytes, 60, string_ids_offset);
    compact_fixture_write_u32(bytes, 64, type_count);
    compact_fixture_write_u32(bytes, 68, type_ids_offset);
    compact_fixture_write_u32(bytes, 72, proto_count);
    compact_fixture_write_u32(bytes, 76, proto_ids_offset);
    compact_fixture_write_u32(bytes, 88, method_count);
    compact_fixture_write_u32(bytes, 92, method_ids_offset);
    compact_fixture_write_u32(bytes, 96, class_count);
    compact_fixture_write_u32(bytes, 100, class_defs_offset);
    compact_fixture_write_u32(bytes, 104, data_size);
    compact_fixture_write_u32(bytes, 108, main_size);
    compact_fixture_write_u32(bytes, 112, 0);
    compact_fixture_write_u32(bytes, 116, debug_table_position);
    compact_fixture_write_u32(bytes, 120, debug_table_offset);
    compact_fixture_write_u32(bytes, 124, fixture.debug_info_offset);
    compact_fixture_write_u32(bytes, 128, 0);
    compact_fixture_write_u32(bytes, 132, data_size);

    compact_fixture_write_u32(bytes, string_ids_offset, 0);
    compact_fixture_write_u32(bytes, string_ids_offset + 4U, 8);
    compact_fixture_write_u32(bytes, string_ids_offset + 8U, 11);
    compact_fixture_write_u32(bytes, string_ids_offset + 12U, 14);
    compact_fixture_write_u32(bytes, type_ids_offset, 0);
    compact_fixture_write_u32(bytes, type_ids_offset + 4U, 1);
    compact_fixture_write_u32(bytes, proto_ids_offset, 1);
    compact_fixture_write_u32(bytes, proto_ids_offset + 4U, 1);
    compact_fixture_write_u32(bytes, proto_ids_offset + 8U, 0);
    compact_fixture_write_u16(bytes, method_ids_offset, 0);
    compact_fixture_write_u16(bytes, method_ids_offset + 2U, 0);
    compact_fixture_write_u32(bytes, method_ids_offset + 4U, 2);
    compact_fixture_write_u16(bytes, method_ids_offset + 8U, 0);
    compact_fixture_write_u16(bytes, method_ids_offset + 10U, 0);
    compact_fixture_write_u32(bytes, method_ids_offset + 12U, 3);
    compact_fixture_write_u32(bytes, class_defs_offset, 0);
    compact_fixture_write_u32(bytes, class_defs_offset + 4U, 1);
    compact_fixture_write_u32(bytes, class_defs_offset + 8U, 0xffffffffU);
    compact_fixture_write_u32(bytes, class_defs_offset + 16U, 0xffffffffU);
    compact_fixture_write_u32(bytes, class_defs_offset + 24U,
        class_data_offset);

    bytes[data] = 6;
    std::memcpy(bytes.data() + data + 1U, "LTest;", 6);
    bytes[data + 7U] = 0;
    bytes[data + 8U] = 1;
    bytes[data + 9U] = 'V';
    bytes[data + 10U] = 0;
    bytes[data + 11U] = 1;
    bytes[data + 12U] = 'm';
    bytes[data + 13U] = 0;
    bytes[data + 14U] = 1;
    bytes[data + 15U] = 'n';
    bytes[data + 16U] = 0;

    bytes[data + class_data_offset] = 0;
    bytes[data + class_data_offset + 1U] = 0;
    bytes[data + class_data_offset + 2U] = 2;
    bytes[data + class_data_offset + 3U] = 0;
    bytes[data + class_data_offset + 4U] = 0;
    bytes[data + class_data_offset + 5U] = 9;
    bytes[data + class_data_offset + 6U] =
        static_cast<std::uint8_t>(fixture.code_item_offset);
    bytes[data + class_data_offset + 7U] = 1;
    bytes[data + class_data_offset + 8U] = 9;
    bytes[data + class_data_offset + 9U] =
        static_cast<std::uint8_t>(fixture.code_item_offset);

    if (extended_register_preheader)
        compact_fixture_write_u16(bytes, data + 30U, 16);
    compact_fixture_write_u16(bytes, data + fixture.code_item_offset,
        extended_register_preheader ? 0U : 0x1000U);
    compact_fixture_write_u16(bytes, data + fixture.code_item_offset + 2U,
        static_cast<std::uint16_t>(0x20U |
            (extended_register_preheader ? 0x01U : 0U)));
    compact_fixture_write_u16(bytes, data + fixture.instructions_offset,
        0x000eU);
    bytes[data + fixture.debug_info_offset] = 1;
    bytes[data + fixture.debug_info_offset + 1U] = 0;
    bytes[data + fixture.debug_info_offset + 2U] = 0;
    bytes[data + fixture.second_debug_info_offset] = 2;
    bytes[data + fixture.second_debug_info_offset + 1U] = 0;
    bytes[data + fixture.second_debug_info_offset + 2U] = 0;

    compact_fixture_write_u32(bytes, data + map_offset, 11);
    const auto write_map = [&](std::uint32_t index, std::uint16_t type,
                               std::uint32_t size, std::uint32_t offset) {
        const auto item = data + map_offset + 4U + index * 12U;
        compact_fixture_write_u16(bytes, item, type);
        compact_fixture_write_u16(bytes, item + 2U, 0);
        compact_fixture_write_u32(bytes, item + 4U, size);
        compact_fixture_write_u32(bytes, item + 8U, offset);
    };
    write_map(0, 0x0000U, 1, 0);
    write_map(1, 0x0001U, string_count, string_ids_offset);
    write_map(2, 0x0002U, type_count, type_ids_offset);
    write_map(3, 0x0003U, proto_count, proto_ids_offset);
    write_map(4, 0x0005U, method_count, method_ids_offset);
    write_map(5, 0x0006U, class_count, class_defs_offset);
    write_map(6, 0x2002U, string_count, 0);
    write_map(7, 0x2000U, 1, class_data_offset);
    write_map(8, 0x2001U, 1, fixture.code_item_offset);
    write_map(9, 0x2003U, 2, fixture.debug_info_offset);
    write_map(10, 0x1000U, 1, map_offset);

    bytes[data + debug_table_position] = 0;
    bytes[data + debug_table_position + 1U] = 3;
    bytes[data + debug_table_position + 2U] = 0;
    bytes[data + debug_table_position + 3U] = 3;
    compact_fixture_write_u32(bytes,
        data + debug_table_position + debug_table_offset, 0);
    return fixture;
}

inline std::vector<std::uint8_t> make_compact_vdex_fixture(
    const compact_dex_fixture_t& dex) {
    std::vector<std::uint8_t> bytes(64U + dex.bytes.size(), 0);
    bytes[0] = 'v';
    bytes[1] = 'd';
    bytes[2] = 'e';
    bytes[3] = 'x';
    bytes[4] = '0';
    bytes[5] = '1';
    bytes[6] = '9';
    bytes[7] = 0;
    std::memcpy(bytes.data() + 64U, dex.bytes.data(), dex.bytes.size());
    return bytes;
}

}
