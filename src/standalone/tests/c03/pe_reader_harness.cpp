#include "pe_reader_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

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
	assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(std::string(message));
}

template <typename value_t>
value_t require_value(workspace_result_t<value_t> result, std::string_view message) {
	const bool accepted = static_cast<bool>(result);
	assertion_telemetry::record_assertion(accepted, message, __FILE__, __LINE__);
    if (!accepted)
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

std::vector<std::uint8_t> make_pe_positive_fixture() {
    constexpr std::uint64_t k_pos_image_base = 0x0000000140000000ULL;
    constexpr std::size_t k_pos_optional_offset = 0x98U;
    constexpr std::size_t k_pos_section_offset = 0x188U;
    constexpr std::size_t k_pos_dir_offset = 0x108U;
    constexpr std::size_t k_pos_dir_count_offset = 0x104U;
    constexpr std::size_t k_pos_image_size = 0x5000U;
    constexpr std::size_t k_pos_headers_size = 0x400U;
    constexpr std::uint32_t k_dir_export = 0U;
    constexpr std::uint32_t k_dir_import = 1U;
    constexpr std::uint32_t k_dir_basereloc = 5U;
    constexpr std::uint32_t k_dir_tls = 9U;
    constexpr std::uint32_t k_dir_load_config = 10U;

    std::vector<std::uint8_t> bytes(0x1200U);

    bytes[0] = 'M';
    bytes[1] = 'Z';
    write_u32(bytes, 0x3cU, 0x80U);
    bytes[0x80U] = 'P';
    bytes[0x81U] = 'E';
    bytes[0x82U] = 0;
    bytes[0x83U] = 0;

    write_u16(bytes, 0x84U, k_image_file_machine_amd64);
    write_u16(bytes, 0x86U, 4U);
    write_u32(bytes, 0x88U, 0x5f3759dfU);
    write_u16(bytes, 0x94U, 0xf0U);
    write_u16(bytes, 0x96U, 0x0002U);

    write_u16(bytes, k_pos_optional_offset, k_optional_magic_pe32_plus);
    write_u32(bytes, k_pos_optional_offset + 4U, 0x200U);
    write_u32(bytes, k_pos_optional_offset + 8U, 0xA00U);
    write_u32(bytes, k_pos_optional_offset + 16U, 0x1000U);
    write_u32(bytes, k_pos_optional_offset + 20U, 0x1000U);
    write_u64(bytes, k_pos_optional_offset + 24U, k_pos_image_base);
    write_u32(bytes, k_pos_optional_offset + 32U, 0x1000U);
    write_u32(bytes, k_pos_optional_offset + 36U, 0x200U);
    write_u32(bytes, k_pos_optional_offset + 56U, k_pos_image_size);
    write_u32(bytes, k_pos_optional_offset + 60U, k_pos_headers_size);
    write_u16(bytes, k_pos_optional_offset + 68U, 3U);
    write_u16(bytes, k_pos_optional_offset + 70U, 0x0080U);
    write_u32(bytes, k_pos_dir_count_offset, 16U);

    write_u32(bytes, k_pos_dir_offset + k_dir_export * 8U, 0x20A0U);
    write_u32(bytes, k_pos_dir_offset + k_dir_export * 8U + 4U, 40U);
    write_u32(bytes, k_pos_dir_offset + k_dir_import * 8U, 0x2000U);
    write_u32(bytes, k_pos_dir_offset + k_dir_import * 8U + 4U, 40U);
    write_u32(bytes, k_pos_dir_offset + k_dir_basereloc * 8U, 0x4000U);
    write_u32(bytes, k_pos_dir_offset + k_dir_basereloc * 8U + 4U, 14U);
    write_u32(bytes, k_pos_dir_offset + k_dir_tls * 8U, 0x20F8U);
    write_u32(bytes, k_pos_dir_offset + k_dir_tls * 8U + 4U, 40U);
    write_u32(bytes, k_pos_dir_offset + k_dir_load_config * 8U, 0x2130U);
    write_u32(bytes, k_pos_dir_offset + k_dir_load_config * 8U + 4U, 120U);

    {
        const char name[] = ".text";
        std::copy(name, name + 5U, bytes.begin() + k_pos_section_offset);
        write_u32(bytes, k_pos_section_offset + 8U, 0x200U);
        write_u32(bytes, k_pos_section_offset + 12U, 0x1000U);
        write_u32(bytes, k_pos_section_offset + 16U, 0x200U);
        write_u32(bytes, k_pos_section_offset + 20U, 0x400U);
        write_u32(bytes, k_pos_section_offset + 36U, 0x60000020U);
    }
    {
        const std::size_t off = k_pos_section_offset + 40U;
        const char name[] = ".rdata";
        std::copy(name, name + 6U, bytes.begin() + off);
        write_u32(bytes, off + 8U, 0x1000U);
        write_u32(bytes, off + 12U, 0x2000U);
        write_u32(bytes, off + 16U, 0x800U);
        write_u32(bytes, off + 20U, 0x600U);
        write_u32(bytes, off + 36U, 0x40000040U);
    }
    {
        const std::size_t off = k_pos_section_offset + 80U;
        const char name[] = ".data";
        std::copy(name, name + 5U, bytes.begin() + off);
        write_u32(bytes, off + 8U, 0x200U);
        write_u32(bytes, off + 12U, 0x3000U);
        write_u32(bytes, off + 16U, 0x200U);
        write_u32(bytes, off + 20U, 0xE00U);
        write_u32(bytes, off + 36U, 0xC0000040U);
    }
    {
        const std::size_t off = k_pos_section_offset + 120U;
        const char name[] = ".reloc";
        std::copy(name, name + 6U, bytes.begin() + off);
        write_u32(bytes, off + 8U, 0x200U);
        write_u32(bytes, off + 12U, 0x4000U);
        write_u32(bytes, off + 16U, 0x200U);
        write_u32(bytes, off + 20U, 0x1000U);
        write_u32(bytes, off + 36U, 0x42000040U);
    }

    bytes[0x400U] = 0xc3U;

    write_u32(bytes, 0x600U, 0x2040U);
    write_u32(bytes, 0x604U, 0U);
    write_u32(bytes, 0x608U, 0U);
    write_u32(bytes, 0x60cU, 0x2030U);
    write_u32(bytes, 0x610U, 0x2060U);

    const char dll_name[] = "kernel32.dll";
    std::copy(dll_name, dll_name + 13U, bytes.begin() + 0x630U);

    write_u64(bytes, 0x640U, 0x2080U);
    write_u64(bytes, 0x648U, 0x2090U);
    write_u64(bytes, 0x650U, 0U);

    write_u64(bytes, 0x660U, 0x2080U);
    write_u64(bytes, 0x668U, 0x2090U);
    write_u64(bytes, 0x670U, 0U);

    write_u16(bytes, 0x680U, 0U);
    const char func1[] = "CreateFileW";
    std::copy(func1, func1 + 12U, bytes.begin() + 0x682U);

    write_u16(bytes, 0x690U, 0U);
    const char func2[] = "WriteFile";
    std::copy(func2, func2 + 10U, bytes.begin() + 0x692U);

    write_u32(bytes, 0x6A0U, 0U);
    write_u32(bytes, 0x6A4U, 0U);
    write_u16(bytes, 0x6A8U, 0U);
    write_u16(bytes, 0x6AAU, 0U);
    write_u32(bytes, 0x6AcU, 0x20D0U);
    write_u32(bytes, 0x6B0U, 1U);
    write_u32(bytes, 0x6B4U, 2U);
    write_u32(bytes, 0x6B8U, 2U);
    write_u32(bytes, 0x6BcU, 0x20C8U);
    write_u32(bytes, 0x6C0U, 0x20E0U);
    write_u32(bytes, 0x6C4U, 0x20E8U);

    write_u32(bytes, 0x6C8U, 0x1000U);
    write_u32(bytes, 0x6CcU, 0x1010U);

    const char exp_dll[] = "aidatest.dll";
    std::copy(exp_dll, exp_dll + 13U, bytes.begin() + 0x6D0U);

    write_u32(bytes, 0x6E0U, 0x20ECU);
    write_u32(bytes, 0x6E4U, 0x20F2U);

    write_u16(bytes, 0x6E8U, 0x0000U);
    write_u16(bytes, 0x6EAU, 0x0001U);

    const char exp_a[] = "FuncA";
    std::copy(exp_a, exp_a + 6U, bytes.begin() + 0x6ECU);
    const char exp_b[] = "FuncB";
    std::copy(exp_b, exp_b + 6U, bytes.begin() + 0x6F2U);

    write_u64(bytes, 0x6F8U, k_pos_image_base + 0x3000U);
    write_u64(bytes, 0x700U, k_pos_image_base + 0x3010U);
    write_u64(bytes, 0x708U, k_pos_image_base + 0x3020U);
    write_u64(bytes, 0x710U, k_pos_image_base + 0x2120U);
    write_u32(bytes, 0x718U, 0U);
    write_u32(bytes, 0x71cU, 0U);

    write_u64(bytes, 0x720U, k_pos_image_base + 0x1000U);
    write_u64(bytes, 0x728U, 0U);

    write_u32(bytes, 0x730U, 120U);
    write_u64(bytes, 0x730U + 80U, k_pos_image_base + 0x3000U);

    write_u32(bytes, 0x1000U, 0x1000U);
    write_u32(bytes, 0x1004U, 14U);
    write_u16(bytes, 0x1008U, 0xA010U);
    write_u16(bytes, 0x100aU, 0xA020U);
    write_u16(bytes, 0x100cU, 0xA030U);

    return bytes;
}

std::vector<std::uint8_t> make_coff_positive_fixture() {
    std::vector<std::uint8_t> bytes(0x7EU);

    write_u16(bytes, 0U, k_image_file_machine_amd64);
    write_u16(bytes, 2U, 1U);
    write_u32(bytes, 4U, 0x12345678U);
    write_u32(bytes, 8U, 0x56U);
    write_u32(bytes, 12U, 2U);
    write_u16(bytes, 16U, 0U);
    write_u16(bytes, 18U, 0U);

    const char section_name[] = ".text";
    std::copy(section_name, section_name + 5U, bytes.begin() + 20U);
    write_u32(bytes, 28U, 0U);
    write_u32(bytes, 32U, 0U);
    write_u32(bytes, 36U, 16U);
    write_u32(bytes, 40U, 60U);
    write_u32(bytes, 44U, 76U);
    write_u32(bytes, 48U, 0U);
    write_u16(bytes, 52U, 1U);
    write_u16(bytes, 54U, 0U);
    write_u32(bytes, 56U, k_section_characteristics_code);

    for (std::size_t i = 0; i < 16U; ++i)
        bytes[60U + i] = 0xc3U;

    write_u32(bytes, 76U, 4U);
    write_u32(bytes, 80U, 0U);
    write_u16(bytes, 84U, 0x0004U);

    const char sym1[] = {'_', 'f', 'u', 'n', 'c', 'A', 0, 0};
    std::copy(sym1, sym1 + 8U, bytes.begin() + 86U);
    write_u32(bytes, 94U, 0U);
    write_u16(bytes, 98U, 1U);
    write_u16(bytes, 100U, 0x0020U);
    bytes[102U] = 2U;
    bytes[103U] = 0U;

    const char sym2[] = {'_', 'f', 'u', 'n', 'c', 'B', 0, 0};
    std::copy(sym2, sym2 + 8U, bytes.begin() + 104U);
    write_u32(bytes, 112U, 8U);
    write_u16(bytes, 116U, 1U);
    write_u16(bytes, 118U, 0x0020U);
    bytes[120U] = 2U;
    bytes[121U] = 0U;

    write_u32(bytes, 122U, 4U);

    return bytes;
}

void verify_positive_data_directories(const std::filesystem::path& root) {
    const auto provider = write_provider(root, "pe_positive.bin",
                                         make_pe_positive_fixture());
    const auto result = require_value(read_pe_coff_metadata(*provider),
                                      "PE reader rejected positive fixture");
    require(result.record.pe.has_value() && !result.record.coff.has_value(),
            "PE reader emitted an invalid record kind for positive fixture");
    const auto& pe = *result.record.pe;

    require(!pe.imports.empty(), "PE reader produced empty imports for positive fixture");
    bool found_kernel32 = false;
    for (const auto& imp : pe.imports) {
        if (imp.library.find("kernel32.dll") != std::string::npos) {
            found_kernel32 = true;
            break;
        }
    }
    require(found_kernel32, "PE reader did not surface kernel32.dll import");

    require(pe.exports.size() == 2U, "PE reader produced wrong export count for positive fixture");
    bool found_func_a = false;
    bool found_func_b = false;
    for (const auto& exp : pe.exports) {
        if (exp.name && *exp.name == "FuncA")
            found_func_a = true;
        if (exp.name && *exp.name == "FuncB")
            found_func_b = true;
    }
    require(found_func_a && found_func_b,
            "PE reader did not surface expected export names");

    require(!pe.relocations.empty(), "PE reader produced empty relocations for positive fixture");
    require(pe.relocations.size() == 3U,
            "PE reader produced wrong relocation count for positive fixture");

    require(!pe.tls_callbacks.empty(), "PE reader produced empty TLS callbacks for positive fixture");
    require(pe.tls_callbacks.size() == 1U,
            "PE reader produced wrong TLS callback count for positive fixture");

    require(pe.load_config.has_value(),
            "PE reader did not surface load config for positive fixture");
    require(pe.load_config->security_cookie_rva.has_value(),
            "PE reader did not surface security cookie in load config");
}

void verify_coff_positive_metadata(const std::filesystem::path& root) {
    const auto provider = write_provider(root, "coff_positive.obj",
                                         make_coff_positive_fixture());
    const auto result = require_value(read_pe_coff_metadata(*provider),
                                      "COFF reader rejected positive fixture");
    require(!result.record.pe.has_value() && result.record.coff.has_value(),
            "COFF reader emitted an invalid record kind for positive fixture");
    const auto& coff = *result.record.coff;

    require(coff.symbols.size() == 2U,
            "COFF reader produced wrong symbol count for positive fixture");
    bool found_func_a = false;
    bool found_func_b = false;
    for (const auto& sym : coff.symbols) {
        if (sym.name == "_funcA" && sym.is_external && sym.is_function && sym.is_defined)
            found_func_a = true;
        if (sym.name == "_funcB" && sym.is_external && sym.is_function && sym.is_defined)
            found_func_b = true;
    }
    require(found_func_a && found_func_b,
            "COFF reader did not surface expected symbol metadata");

    require(coff.relocations.size() == 1U,
            "COFF reader produced wrong relocation count for positive fixture");
    const auto& reloc = coff.relocations.front();
    require(reloc.virtual_address == 4U && reloc.symbol_table_index == 0U &&
                reloc.type == 0x0004U && reloc.normalized_address.has_value(),
            "COFF reader did not surface expected relocation metadata");
}

std::vector<std::uint8_t> make_pe_delay_import_fixture() {
    constexpr std::uint64_t k_image_base = 0x0000000140000000ULL;
    constexpr std::size_t k_optional_offset = 0x98U;
    constexpr std::size_t k_section_offset = 0x188U;
    constexpr std::size_t k_dir_offset = 0x108U;
    constexpr std::size_t k_dir_count_offset = 0x104U;
    constexpr std::size_t k_image_size = 0x3000U;
    constexpr std::size_t k_headers_size = 0x400U;
    constexpr std::uint32_t k_dir_delay_import = 13U;

    std::vector<std::uint8_t> bytes(0x1000U);

    bytes[0] = 'M';
    bytes[1] = 'Z';
    write_u32(bytes, 0x3cU, 0x80U);
    bytes[0x80U] = 'P';
    bytes[0x81U] = 'E';
    bytes[0x82U] = 0;
    bytes[0x83U] = 0;

    write_u16(bytes, 0x84U, k_image_file_machine_amd64);
    write_u16(bytes, 0x86U, 2U);
    write_u32(bytes, 0x88U, 0x5f3759dfU);
    write_u16(bytes, 0x94U, 0xf0U);
    write_u16(bytes, 0x96U, 0x0002U);

    write_u16(bytes, k_optional_offset, k_optional_magic_pe32_plus);
    write_u32(bytes, k_optional_offset + 4U, 0x200U);
    write_u32(bytes, k_optional_offset + 8U, 0xA00U);
    write_u32(bytes, k_optional_offset + 16U, 0x1000U);
    write_u32(bytes, k_optional_offset + 20U, 0x1000U);
    write_u64(bytes, k_optional_offset + 24U, k_image_base);
    write_u32(bytes, k_optional_offset + 32U, 0x1000U);
    write_u32(bytes, k_optional_offset + 36U, 0x200U);
    write_u32(bytes, k_optional_offset + 56U, k_image_size);
    write_u32(bytes, k_optional_offset + 60U, k_headers_size);
    write_u16(bytes, k_optional_offset + 68U, 3U);
    write_u16(bytes, k_optional_offset + 70U, 0x0080U);
    write_u32(bytes, k_dir_count_offset, 16U);

    write_u32(bytes, k_dir_offset + k_dir_delay_import * 8U, 0x2000U);
    write_u32(bytes, k_dir_offset + k_dir_delay_import * 8U + 4U, 64U);

    {
        const char name[] = ".text";
        std::copy(name, name + 5U, bytes.begin() + k_section_offset);
        write_u32(bytes, k_section_offset + 8U, 0x200U);
        write_u32(bytes, k_section_offset + 12U, 0x1000U);
        write_u32(bytes, k_section_offset + 16U, 0x200U);
        write_u32(bytes, k_section_offset + 20U, 0x400U);
        write_u32(bytes, k_section_offset + 36U, 0x60000020U);
    }
    {
        const std::size_t off = k_section_offset + 40U;
        const char name[] = ".rdata";
        std::copy(name, name + 6U, bytes.begin() + off);
        write_u32(bytes, off + 8U, 0x800U);
        write_u32(bytes, off + 12U, 0x2000U);
        write_u32(bytes, off + 16U, 0x800U);
        write_u32(bytes, off + 20U, 0x600U);
        write_u32(bytes, off + 36U, 0x40000040U);
    }

    bytes[0x400U] = 0xc3U;

    write_u32(bytes, 0x600U, 1U);
    write_u32(bytes, 0x604U, 0x2080U);
    write_u32(bytes, 0x608U, 0U);
    write_u32(bytes, 0x60cU, 0x2040U);
    write_u32(bytes, 0x610U, 0x2060U);
    write_u32(bytes, 0x614U, 0U);
    write_u32(bytes, 0x618U, 0U);
    write_u32(bytes, 0x61cU, 0U);

    write_u64(bytes, 0x660U, 0x2090U);
    write_u64(bytes, 0x668U, 0x20A0U);
    write_u64(bytes, 0x670U, 0U);

    const char dll_name[] = "delaytest.dll";
    std::copy(dll_name, dll_name + 14U, bytes.begin() + 0x680U);

    write_u16(bytes, 0x690U, 0U);
    const char func1[] = "DelayFuncA";
    std::copy(func1, func1 + 11U, bytes.begin() + 0x692U);

    write_u16(bytes, 0x6A0U, 0U);
    const char func2[] = "DelayFuncB";
    std::copy(func2, func2 + 11U, bytes.begin() + 0x6A2U);

    return bytes;
}

void verify_delay_import_directory(const std::filesystem::path& root) {
    const auto provider = write_provider(root, "pe_delay_import.bin",
                                         make_pe_delay_import_fixture());
    const auto result = require_value(read_pe_coff_metadata(*provider),
                                       "PE reader rejected delay import fixture");
    require(result.record.pe.has_value(),
            "PE reader emitted an invalid record kind for delay import fixture");
    const auto& pe = *result.record.pe;

    require(!pe.imports.empty(),
            "PE reader produced empty imports for delay import fixture");
    bool found_delay = false;
    for (const auto& imp : pe.imports) {
        if (imp.delayed && imp.library.find("delaytest.dll") != std::string::npos) {
            found_delay = true;
            break;
        }
    }
    require(found_delay, "PE reader did not surface delay import entry");

    bool found_func_a = false;
    bool found_func_b = false;
    for (const auto& imp : pe.imports) {
        if (imp.delayed && imp.library.find("delaytest.dll") != std::string::npos) {
            if (imp.name && *imp.name == "DelayFuncA")
                found_func_a = true;
            if (imp.name && *imp.name == "DelayFuncB")
                found_func_b = true;
        }
    }
    require(found_func_a && found_func_b,
            "PE reader did not surface expected delay import function names");
}

std::vector<std::uint8_t> make_pe_exception_fixture() {
    constexpr std::uint64_t k_image_base = 0x0000000140000000ULL;
    constexpr std::size_t k_optional_offset = 0x98U;
    constexpr std::size_t k_section_offset = 0x188U;
    constexpr std::size_t k_dir_offset = 0x108U;
    constexpr std::size_t k_dir_count_offset = 0x104U;
    constexpr std::size_t k_image_size = 0x3000U;
    constexpr std::size_t k_headers_size = 0x400U;
    constexpr std::uint32_t k_dir_exception = 3U;

    std::vector<std::uint8_t> bytes(0x1000U);

    bytes[0] = 'M';
    bytes[1] = 'Z';
    write_u32(bytes, 0x3cU, 0x80U);
    bytes[0x80U] = 'P';
    bytes[0x81U] = 'E';
    bytes[0x82U] = 0;
    bytes[0x83U] = 0;

    write_u16(bytes, 0x84U, k_image_file_machine_amd64);
    write_u16(bytes, 0x86U, 2U);
    write_u32(bytes, 0x88U, 0x5f3759dfU);
    write_u16(bytes, 0x94U, 0xf0U);
    write_u16(bytes, 0x96U, 0x0002U);

    write_u16(bytes, k_optional_offset, k_optional_magic_pe32_plus);
    write_u32(bytes, k_optional_offset + 4U, 0x200U);
    write_u32(bytes, k_optional_offset + 8U, 0xA00U);
    write_u32(bytes, k_optional_offset + 16U, 0x1000U);
    write_u32(bytes, k_optional_offset + 20U, 0x1000U);
    write_u64(bytes, k_optional_offset + 24U, k_image_base);
    write_u32(bytes, k_optional_offset + 32U, 0x1000U);
    write_u32(bytes, k_optional_offset + 36U, 0x200U);
    write_u32(bytes, k_optional_offset + 56U, k_image_size);
    write_u32(bytes, k_optional_offset + 60U, k_headers_size);
    write_u16(bytes, k_optional_offset + 68U, 3U);
    write_u16(bytes, k_optional_offset + 70U, 0x0080U);
    write_u32(bytes, k_dir_count_offset, 16U);

    write_u32(bytes, k_dir_offset + k_dir_exception * 8U, 0x2000U);
    write_u32(bytes, k_dir_offset + k_dir_exception * 8U + 4U, 12U);

    {
        const char name[] = ".text";
        std::copy(name, name + 5U, bytes.begin() + k_section_offset);
        write_u32(bytes, k_section_offset + 8U, 0x200U);
        write_u32(bytes, k_section_offset + 12U, 0x1000U);
        write_u32(bytes, k_section_offset + 16U, 0x200U);
        write_u32(bytes, k_section_offset + 20U, 0x400U);
        write_u32(bytes, k_section_offset + 36U, 0x60000020U);
    }
    {
        const std::size_t off = k_section_offset + 40U;
        const char name[] = ".rdata";
        std::copy(name, name + 6U, bytes.begin() + off);
        write_u32(bytes, off + 8U, 0x800U);
        write_u32(bytes, off + 12U, 0x2000U);
        write_u32(bytes, off + 16U, 0x800U);
        write_u32(bytes, off + 20U, 0x600U);
        write_u32(bytes, off + 36U, 0x40000040U);
    }

    bytes[0x400U] = 0xc3U;

    write_u32(bytes, 0x600U, 0x1000U);
    write_u32(bytes, 0x604U, 0x1010U);
    write_u32(bytes, 0x608U, 0x2020U);

    bytes[0x620U] = 0x01U;
    bytes[0x621U] = 0x05U;
    bytes[0x622U] = 0x01U;
    bytes[0x623U] = 0x00U;

    bytes[0x624U] = 0x05U;
    bytes[0x625U] = 0x60U;

    return bytes;
}

void verify_exception_directory(const std::filesystem::path& root) {
    const auto provider = write_provider(root, "pe_exception.bin",
                                         make_pe_exception_fixture());
    const auto result = require_value(read_pe_coff_metadata(*provider),
                                       "PE reader rejected exception fixture");
    require(result.record.pe.has_value(),
            "PE reader emitted an invalid record kind for exception fixture");
    const auto& pe = *result.record.pe;

    require(!pe.runtime_functions.empty(),
            "PE reader produced empty runtime functions for exception fixture");
    require(pe.runtime_functions.size() == 1U,
            "PE reader produced wrong runtime function count for exception fixture");
    const auto& rf = pe.runtime_functions.front();
    require(rf.begin_rva == 0x1000U && rf.end_rva == 0x1010U &&
                rf.unwind_rva == 0x2020U,
            "PE reader did not surface expected runtime function addresses");

    require(!pe.unwind_records.empty(),
            "PE reader produced empty unwind records for exception fixture");
    require(pe.unwind_records.size() == 1U,
            "PE reader produced wrong unwind record count for exception fixture");
    const auto& ur = pe.unwind_records.front();
    require(ur.version == 1U && ur.flags == 0U && ur.prolog_size == 5U,
            "PE reader did not surface expected unwind header values");
    require(ur.codes.size() == 1U,
            "PE reader did not surface expected unwind code count");
    require(ur.codes.front().operation == pe_unwind_operation_t::push_nonvolatile &&
                ur.codes.front().operation_info == 6U &&
                ur.codes.front().code_offset == 5U,
            "PE reader did not surface expected unwind code details");
}

std::vector<std::uint8_t> make_pe_debug_fixture() {
    constexpr std::uint64_t k_image_base = 0x0000000140000000ULL;
    constexpr std::size_t k_optional_offset = 0x98U;
    constexpr std::size_t k_section_offset = 0x188U;
    constexpr std::size_t k_dir_offset = 0x108U;
    constexpr std::size_t k_dir_count_offset = 0x104U;
    constexpr std::size_t k_image_size = 0x3000U;
    constexpr std::size_t k_headers_size = 0x400U;
    constexpr std::uint32_t k_dir_debug = 6U;

    std::vector<std::uint8_t> bytes(0x1000U);

    bytes[0] = 'M';
    bytes[1] = 'Z';
    write_u32(bytes, 0x3cU, 0x80U);
    bytes[0x80U] = 'P';
    bytes[0x81U] = 'E';
    bytes[0x82U] = 0;
    bytes[0x83U] = 0;

    write_u16(bytes, 0x84U, k_image_file_machine_amd64);
    write_u16(bytes, 0x86U, 2U);
    write_u32(bytes, 0x88U, 0x5f3759dfU);
    write_u16(bytes, 0x94U, 0xf0U);
    write_u16(bytes, 0x96U, 0x0002U);

    write_u16(bytes, k_optional_offset, k_optional_magic_pe32_plus);
    write_u32(bytes, k_optional_offset + 4U, 0x200U);
    write_u32(bytes, k_optional_offset + 8U, 0xA00U);
    write_u32(bytes, k_optional_offset + 16U, 0x1000U);
    write_u32(bytes, k_optional_offset + 20U, 0x1000U);
    write_u64(bytes, k_optional_offset + 24U, k_image_base);
    write_u32(bytes, k_optional_offset + 32U, 0x1000U);
    write_u32(bytes, k_optional_offset + 36U, 0x200U);
    write_u32(bytes, k_optional_offset + 56U, k_image_size);
    write_u32(bytes, k_optional_offset + 60U, k_headers_size);
    write_u16(bytes, k_optional_offset + 68U, 3U);
    write_u16(bytes, k_optional_offset + 70U, 0x0080U);
    write_u32(bytes, k_dir_count_offset, 16U);

    write_u32(bytes, k_dir_offset + k_dir_debug * 8U, 0x2000U);
    write_u32(bytes, k_dir_offset + k_dir_debug * 8U + 4U, 28U);

    {
        const char name[] = ".text";
        std::copy(name, name + 5U, bytes.begin() + k_section_offset);
        write_u32(bytes, k_section_offset + 8U, 0x200U);
        write_u32(bytes, k_section_offset + 12U, 0x1000U);
        write_u32(bytes, k_section_offset + 16U, 0x200U);
        write_u32(bytes, k_section_offset + 20U, 0x400U);
        write_u32(bytes, k_section_offset + 36U, 0x60000020U);
    }
    {
        const std::size_t off = k_section_offset + 40U;
        const char name[] = ".rdata";
        std::copy(name, name + 6U, bytes.begin() + off);
        write_u32(bytes, off + 8U, 0x800U);
        write_u32(bytes, off + 12U, 0x2000U);
        write_u32(bytes, off + 16U, 0x800U);
        write_u32(bytes, off + 20U, 0x600U);
        write_u32(bytes, off + 36U, 0x40000040U);
    }

    bytes[0x400U] = 0xc3U;

    write_u32(bytes, 0x600U, 0U);
    write_u32(bytes, 0x604U, 0x12345678U);
    write_u16(bytes, 0x608U, 0U);
    write_u16(bytes, 0x60AU, 0U);
    write_u32(bytes, 0x60CU, 2U);
    write_u32(bytes, 0x610U, 33U);
    write_u32(bytes, 0x614U, 0x2020U);
    write_u32(bytes, 0x618U, 0x620U);

    bytes[0x620U] = 'R';
    bytes[0x621U] = 'S';
    bytes[0x622U] = 'D';
    bytes[0x623U] = 'S';

    bytes[0x624U] = 0xAAU;
    bytes[0x625U] = 0xBBU;
    bytes[0x626U] = 0xCCU;
    bytes[0x627U] = 0xDDU;
    bytes[0x628U] = 0xEEU;
    bytes[0x629U] = 0xFFU;
    bytes[0x62AU] = 0x01U;
    bytes[0x62BU] = 0x02U;
    bytes[0x62CU] = 0x03U;
    bytes[0x62DU] = 0x04U;
    bytes[0x62EU] = 0x05U;
    bytes[0x62FU] = 0x06U;
    bytes[0x630U] = 0x07U;
    bytes[0x631U] = 0x08U;
    bytes[0x632U] = 0x09U;
    bytes[0x633U] = 0x0AU;

    write_u32(bytes, 0x634U, 7U);

    const char pdb_path[] = "test.pdb";
    std::copy(pdb_path, pdb_path + 9U, bytes.begin() + 0x638U);

    return bytes;
}

void verify_debug_directory(const std::filesystem::path& root) {
    const auto provider = write_provider(root, "pe_debug.bin",
                                         make_pe_debug_fixture());
    const auto result = require_value(read_pe_coff_metadata(*provider),
                                       "PE reader rejected debug fixture");
    require(result.record.pe.has_value(),
            "PE reader emitted an invalid record kind for debug fixture");
    const auto& pe = *result.record.pe;

    require(!pe.codeview_records.empty(),
            "PE reader produced empty codeview records for debug fixture");
    require(pe.codeview_records.size() == 1U,
            "PE reader produced wrong codeview record count for debug fixture");
    const auto& cv = pe.codeview_records.front();
    require(cv.pdb_path == "test.pdb",
            "PE reader did not surface expected PDB path");
    require(cv.age == 7U,
            "PE reader did not surface expected CodeView age");
    require(cv.timestamp == 0x12345678U,
            "PE reader did not surface expected debug timestamp");
    require(cv.guid[0] == 0xAAU && cv.guid[1] == 0xBBU &&
                cv.guid[15] == 0x0AU,
            "PE reader did not surface expected CodeView GUID");
}

}

void run_pe_reader_harness(const std::filesystem::path& root) {
    std::filesystem::create_directories(root);
    try {
        verify_pe_fixture(root, false);
        verify_pe_fixture(root, true);
        verify_coff_fixture(root);
        verify_malformed_fixtures(root);
        verify_positive_data_directories(root);
        verify_coff_positive_metadata(root);
        verify_delay_import_directory(root);
        verify_exception_directory(root);
        verify_debug_directory(root);
        for (const auto& name : {"pe32.bin", "pe64.bin", "coff.obj", "malformed_cli.bin",
                                 "truncated_pe.bin", "invalid_coff.bin",
                                 "pe_positive.bin", "coff_positive.obj",
                                 "pe_delay_import.bin", "pe_exception.bin",
                                 "pe_debug.bin"}) {
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
