#include "pe_reader_harness.hpp"

#include "../../src/core/analysis/readers/pe_coff_reader.hpp"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aida::analysis::c03_test {
namespace {

constexpr std::uint16_t k_image_file_machine_i386 = 0x014cU;
constexpr std::uint16_t k_image_file_machine_amd64 = 0x8664U;
constexpr std::uint16_t k_optional_magic_pe32 = 0x010bU;
constexpr std::uint16_t k_optional_magic_pe32_plus = 0x020bU;
constexpr std::uint32_t k_section_characteristics_code = 0x60000020U;
constexpr std::uint32_t k_cli_directory_index = 14U;

void require(bool condition, std::string_view message) {
    if (!condition)
        throw std::runtime_error(std::string(message));
}

template <typename value_t>
value_t require_value(workspace_result_t<value_t> result, std::string_view message) {
    if (!result)
        throw std::runtime_error(std::string(message) + ":" + result.error().stable_code());
    return result.take_value();
}

void write_u16(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value) {
    require(offset <= bytes.size() && bytes.size() - offset >= 2U, "fixture u16 write escaped buffer");
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
}

void write_u32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
    require(offset <= bytes.size() && bytes.size() - offset >= 4U, "fixture u32 write escaped buffer");
    for (std::size_t index = 0; index < 4U; ++index)
        bytes[offset + index] = static_cast<std::uint8_t>(value >> (index * 8U));
}

void write_u64(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint64_t value) {
    require(offset <= bytes.size() && bytes.size() - offset >= 8U, "fixture u64 write escaped buffer");
    for (std::size_t index = 0; index < 8U; ++index)
        bytes[offset + index] = static_cast<std::uint8_t>(value >> (index * 8U));
}

std::vector<std::uint8_t> make_pe_fixture(bool is_64_bit, bool malformed_cli) {
    const std::size_t optional_size = is_64_bit ? 0xf0U : 0xe0U;
    const std::size_t optional_offset = 0x98U;
    const std::size_t section_offset = optional_offset + optional_size;
    std::vector<std::uint8_t> bytes(0x600U);
    bytes[0] = 'M';
    bytes[1] = 'Z';
    write_u32(bytes, 0x3cU, 0x80U);
    bytes[0x80U] = 'P';
    bytes[0x81U] = 'E';
    write_u16(bytes, 0x84U, is_64_bit ? k_image_file_machine_amd64 : k_image_file_machine_i386);
    write_u16(bytes, 0x86U, 1U);
    write_u32(bytes, 0x88U, 0x5f3759dfU);
    write_u16(bytes, 0x94U, static_cast<std::uint16_t>(optional_size));
    write_u16(bytes, 0x96U, 0x0002U);
    write_u16(bytes, optional_offset, is_64_bit ? k_optional_magic_pe32_plus : k_optional_magic_pe32);
    write_u32(bytes, optional_offset + 16U, 0x1000U);
    write_u32(bytes, optional_offset + 20U, 0x1000U);
    if (is_64_bit)
        write_u64(bytes, optional_offset + 24U, 0x0000000140000000ULL);
    else {
        write_u32(bytes, optional_offset + 24U, 0x1000U);
        write_u32(bytes, optional_offset + 28U, 0x00400000U);
    }
    write_u32(bytes, optional_offset + 32U, 0x1000U);
    write_u32(bytes, optional_offset + 36U, 0x200U);
    write_u32(bytes, optional_offset + 56U, 0x2000U);
    write_u32(bytes, optional_offset + 60U, 0x200U);
    write_u16(bytes, optional_offset + 68U, 3U);
    const std::size_t directory_count_offset = is_64_bit ? optional_offset + 108U : optional_offset + 92U;
    const std::size_t directory_offset = is_64_bit ? optional_offset + 112U : optional_offset + 96U;
    write_u32(bytes, directory_count_offset, 16U);
    write_u32(bytes, directory_offset + k_cli_directory_index * 8U, 0x1100U);
    write_u32(bytes, directory_offset + k_cli_directory_index * 8U + 4U,
              malformed_cli ? 4U : 72U);
    const char section_name[] = ".text";
    std::copy(section_name, section_name + 5U, bytes.begin() + section_offset);
    write_u32(bytes, section_offset + 8U, 0x200U);
    write_u32(bytes, section_offset + 12U, 0x1000U);
    write_u32(bytes, section_offset + 16U, 0x200U);
    write_u32(bytes, section_offset + 20U, 0x200U);
    write_u32(bytes, section_offset + 36U, k_section_characteristics_code);
    write_u32(bytes, 0x300U, 72U);
    write_u16(bytes, 0x304U, 2U);
    write_u16(bytes, 0x306U, 5U);
    write_u32(bytes, 0x308U, 0x1150U);
    write_u32(bytes, 0x30cU, 16U);
    write_u32(bytes, 0x310U, 0x00020009U);
    write_u32(bytes, 0x314U, 0x06000001U);
    bytes[0x350U] = 'B';
    bytes[0x351U] = 'S';
    bytes[0x352U] = 'J';
    bytes[0x353U] = 'B';
    return bytes;
}

std::vector<std::uint8_t> make_coff_fixture() {
    std::vector<std::uint8_t> bytes(0x66U);
    write_u16(bytes, 0U, k_image_file_machine_i386);
    write_u16(bytes, 2U, 1U);
    write_u32(bytes, 4U, 0x10203040U);
    write_u32(bytes, 8U, 0x50U);
    write_u32(bytes, 12U, 1U);
    write_u16(bytes, 16U, 0U);
    write_u16(bytes, 18U, 0U);
    const char section_name[] = ".text";
    std::copy(section_name, section_name + 5U, bytes.begin() + 20U);
    write_u32(bytes, 28U, 4U);
    write_u32(bytes, 36U, 4U);
    write_u32(bytes, 40U, 0x44U);
    write_u32(bytes, 56U, k_section_characteristics_code);
    bytes[0x44U] = 0xc3U;
    const char symbol_name[] = {'?', '?', '_', '7', 'F', 'o', 'o', 0};
    std::copy(symbol_name, symbol_name + 8U, bytes.begin() + 0x50U);
    write_u32(bytes, 0x58U, 0U);
    write_u16(bytes, 0x5cU, 1U);
    write_u16(bytes, 0x5eU, 0x20U);
    bytes[0x60U] = 2U;
    bytes[0x61U] = 0U;
    write_u32(bytes, 0x62U, 4U);
    return bytes;
}

std::shared_ptr<mapped_file_provider_t> write_provider(const std::filesystem::path& root,
                                                        std::string_view name,
                                                        const std::vector<std::uint8_t>& bytes) {
    std::filesystem::create_directories(root);
    const auto path = root / std::string(name);
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    require(stream.good(), "fixture stream open failed");
    stream.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    require(stream.good(), "fixture stream write failed");
    stream.close();
    return require_value(mapped_file_provider_t::open(path.u8string()), "fixture provider open failed");
}

void verify_pe_fixture(const std::filesystem::path& root, bool is_64_bit) {
    const auto provider = write_provider(root, is_64_bit ? "pe64.bin" : "pe32.bin",
                                         make_pe_fixture(is_64_bit, false));
    const auto result = require_value(read_pe_coff_metadata(*provider), "PE reader rejected fixture");
    require(result.record.pe.has_value() && !result.record.coff.has_value(),
            "PE reader emitted an invalid record kind");
    const auto expected_format = is_64_bit ? format_id_t::pe32_plus : format_id_t::pe32;
    const auto expected_width = is_64_bit ? 64U : 32U;
    require(result.record.image.format == expected_format &&
                result.record.image.address_width_bits == expected_width,
            "PE reader format projection drifted");
    require(result.record.pe->cli.has_value(), "PE reader lost CLI metadata");
    const auto& cli = *result.record.pe->cli;
    require(cli.metadata_rva == 0x1150U && cli.il_only && cli.strong_name_signed &&
                cli.preferred_32bit && !cli.requires_32bit && !cli.native_entry_point,
            "PE reader CLI flags drifted");
    require(result.record.pe->sections.size() == 1U && result.record.pe->resources.empty() &&
                result.record.pe->imports.empty() && result.record.pe->exports.empty(),
            "PE reader section or metadata projection drifted");
    const auto lookup = result.layout.lookup_rva(0x1100U);
    require(lookup && lookup.value().has_value() &&
                lookup.value()->file_offset.has_value() && *lookup.value()->file_offset == 0x300U,
            "PE reader layout projection lost CLI header mapping");
}

void verify_coff_fixture(const std::filesystem::path& root) {
    const auto provider = write_provider(root, "coff.obj", make_coff_fixture());
    const auto result = require_value(read_pe_coff_metadata(*provider), "COFF reader rejected fixture");
    require(!result.record.pe.has_value() && result.record.coff.has_value(),
            "COFF reader emitted an invalid record kind");
    require(result.record.image.format == format_id_t::coff &&
                result.record.coff->symbols.size() == 1U &&
                result.record.coff->sections.size() == 1U,
            "COFF normalized record drifted");
    require(result.record.type_seeds.size() == 1U &&
                result.record.type_seeds.front().kind == pe_coff_type_seed_kind_t::vtable &&
                result.record.type_seeds.front().origin == pe_coff_type_seed_origin_t::coff_symbol,
            "COFF RTTI/vtable seed projection drifted");
    const auto lookup = result.layout.lookup_file_offset(0x44U);
    require(lookup && lookup.value().has_value() && lookup.value()->file_offset.has_value() &&
                *lookup.value()->file_offset == 0x44U,
            "COFF layout projection lost section mapping");
}

void verify_malformed_fixtures(const std::filesystem::path& root) {
    auto invalid_pe = make_pe_fixture(false, true);
    const auto malformed_cli = write_provider(root, "malformed_cli.bin", invalid_pe);
    const auto malformed_cli_result = read_pe_coff_metadata(*malformed_cli);
    require(!malformed_cli_result &&
                malformed_cli_result.error().code == workspace_error_code_t::malformed_image,
            "malformed CLI directory was accepted");
    std::vector<std::uint8_t> truncated_pe(64U);
    truncated_pe[0] = 'M';
    truncated_pe[1] = 'Z';
    write_u32(truncated_pe, 0x3cU, 0x80U);
    const auto truncated = write_provider(root, "truncated_pe.bin", truncated_pe);
    const auto truncated_result = read_pe_coff_metadata(*truncated);
    require(!truncated_result, "truncated PE was accepted");
    const std::vector<std::uint8_t> invalid_coff{0U, 0U, 0U, 0U};
    const auto coff = write_provider(root, "invalid_coff.bin", invalid_coff);
    const auto coff_result = read_pe_coff_metadata(*coff);
    require(!coff_result, "malformed COFF was accepted");
}

}

void run_pe_reader_harness(const std::filesystem::path& root) {
    std::filesystem::create_directories(root);
    try {
        verify_pe_fixture(root, false);
        verify_pe_fixture(root, true);
        verify_coff_fixture(root);
        verify_malformed_fixtures(root);
        for (const auto& name : {"pe32.bin", "pe64.bin", "coff.obj", "malformed_cli.bin",
                                 "truncated_pe.bin", "invalid_coff.bin"}) {
            std::error_code ignored;
            std::filesystem::remove(root / name, ignored);
        }
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
        throw;
    }
}

}
