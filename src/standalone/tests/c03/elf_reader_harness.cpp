#include "elf_reader_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/readers/elf_reader.hpp"
#include "../../src/core/analysis/workspace/byte_provider.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace aida::analysis::c03_test {
namespace {

constexpr std::uint64_t rich_base = 0x400000ULL;
constexpr std::size_t rich_file_size = 0xd80U;
constexpr std::size_t rich_program_offset = 0x40U;
constexpr std::size_t rich_section_offset = 0x800U;
constexpr std::size_t rich_dynamic_offset = 0x240U;
constexpr std::size_t rich_dynamic_size = 0xd0U;
constexpr std::size_t rich_dynstr_offset = 0x320U;
constexpr std::size_t rich_dynsym_offset = 0x340U;
constexpr std::size_t rich_rela_offset = 0x370U;
constexpr std::size_t rich_got_offset = 0x390U;
constexpr std::size_t rich_plt_offset = 0x3b0U;
constexpr std::size_t rich_init_offset = 0x3d0U;
constexpr std::size_t rich_fini_offset = 0x3d8U;
constexpr std::size_t rich_note_offset = 0x3e0U;
constexpr std::size_t rich_eh_frame_offset = 0x400U;
constexpr std::size_t rich_eh_frame_header_offset = 0x410U;
constexpr std::size_t rich_exception_offset = 0x420U;
constexpr std::size_t rich_debug_link_offset = 0x430U;
constexpr std::size_t rich_debug_altlink_offset = 0x450U;
constexpr std::size_t rich_debug_info_offset = 0x460U;
constexpr std::size_t rich_debug_types_offset = 0x470U;
constexpr std::size_t rich_debug_names_offset = 0x480U;
constexpr std::size_t rich_strtab_offset = 0x490U;
constexpr std::size_t rich_symtab_offset = 0x4a0U;
constexpr std::size_t rich_shstrtab_offset = 0x500U;

void require(bool condition, const char* message) {
	assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(message);
}

template <typename value_t>
value_t require_value(workspace_result_t<value_t> result, const char* message) {
	const bool accepted = static_cast<bool>(result);
	assertion_telemetry::record_assertion(accepted, message, __FILE__, __LINE__);
    if (!accepted)
        throw std::runtime_error(std::string(message) + ":" + result.error().stable_code());
    return result.take_value();
}

void write_unsigned(std::vector<std::uint8_t>& bytes, std::size_t offset,
                    std::uint64_t value, std::size_t width, bool big_endian) {
    require(width != 0 && width <= sizeof(value) && offset <= bytes.size() &&
                width <= bytes.size() - offset,
            "fixture integer write exceeds its buffer");
    for (std::size_t index = 0; index < width; ++index) {
        const auto shift = static_cast<unsigned int>((big_endian ? width - 1U - index : index) * 8U);
        bytes[offset + index] = static_cast<std::uint8_t>(value >> shift);
    }
}

void write_u16(std::vector<std::uint8_t>& bytes, std::size_t offset,
               std::uint16_t value, bool big_endian) {
    write_unsigned(bytes, offset, value, sizeof(value), big_endian);
}

void write_u32(std::vector<std::uint8_t>& bytes, std::size_t offset,
               std::uint32_t value, bool big_endian) {
    write_unsigned(bytes, offset, value, sizeof(value), big_endian);
}

void write_u64(std::vector<std::uint8_t>& bytes, std::size_t offset,
               std::uint64_t value, bool big_endian) {
    write_unsigned(bytes, offset, value, sizeof(value), big_endian);
}

void write_bytes(std::vector<std::uint8_t>& bytes, std::size_t offset,
                 const std::vector<std::uint8_t>& value) {
    require(offset <= bytes.size() && value.size() <= bytes.size() - offset,
            "fixture byte write exceeds its buffer");
    std::copy(value.begin(), value.end(), bytes.begin() + static_cast<std::ptrdiff_t>(offset));
}

void write_text(std::vector<std::uint8_t>& bytes, std::size_t offset, std::string_view value) {
    require(offset <= bytes.size() && value.size() <= bytes.size() - offset,
            "fixture text write exceeds its buffer");
    std::copy(value.begin(), value.end(), bytes.begin() + static_cast<std::ptrdiff_t>(offset));
}

std::size_t align4(std::size_t value) {
    require(value <= (std::numeric_limits<std::size_t>::max)() - 3U,
            "fixture alignment overflow");
    return (value + 3U) & ~std::size_t{3U};
}

std::size_t append_name(std::vector<std::uint8_t>& table, std::string_view name) {
    const auto offset = table.size();
    table.insert(table.end(), name.begin(), name.end());
    table.push_back(0);
    return offset;
}

void initialize_ident(std::vector<std::uint8_t>& bytes, bool is_64, bool big_endian) {
    require(bytes.size() >= 16U, "fixture ELF identifier exceeds its buffer");
    bytes[0] = 0x7fU;
    bytes[1] = 'E';
    bytes[2] = 'L';
    bytes[3] = 'F';
    bytes[4] = is_64 ? 2U : 1U;
    bytes[5] = big_endian ? 2U : 1U;
    bytes[6] = 1U;
    bytes[7] = 3U;
}

void write_elf64_header(std::vector<std::uint8_t>& bytes, std::uint16_t type,
                        std::uint16_t machine, bool big_endian, std::uint64_t entry,
                        std::uint64_t phoff, std::uint64_t shoff, std::uint16_t phnum,
                        std::uint16_t shnum, std::uint16_t shstrndx) {
    initialize_ident(bytes, true, big_endian);
    write_u16(bytes, 16U, type, big_endian);
    write_u16(bytes, 18U, machine, big_endian);
    write_u32(bytes, 20U, 1U, big_endian);
    write_u64(bytes, 24U, entry, big_endian);
    write_u64(bytes, 32U, phoff, big_endian);
    write_u64(bytes, 40U, shoff, big_endian);
    write_u32(bytes, 48U, 0U, big_endian);
    write_u16(bytes, 52U, 64U, big_endian);
    write_u16(bytes, 54U, 56U, big_endian);
    write_u16(bytes, 56U, phnum, big_endian);
    write_u16(bytes, 58U, 64U, big_endian);
    write_u16(bytes, 60U, shnum, big_endian);
    write_u16(bytes, 62U, shstrndx, big_endian);
}

void write_elf32_header(std::vector<std::uint8_t>& bytes, std::uint16_t type,
                        std::uint16_t machine, bool big_endian, std::uint32_t entry,
                        std::uint32_t phoff, std::uint32_t shoff, std::uint16_t phnum,
                        std::uint16_t shnum, std::uint16_t shstrndx) {
    initialize_ident(bytes, false, big_endian);
    write_u16(bytes, 16U, type, big_endian);
    write_u16(bytes, 18U, machine, big_endian);
    write_u32(bytes, 20U, 1U, big_endian);
    write_u32(bytes, 24U, entry, big_endian);
    write_u32(bytes, 28U, phoff, big_endian);
    write_u32(bytes, 32U, shoff, big_endian);
    write_u32(bytes, 36U, 0U, big_endian);
    write_u16(bytes, 40U, 52U, big_endian);
    write_u16(bytes, 42U, 32U, big_endian);
    write_u16(bytes, 44U, phnum, big_endian);
    write_u16(bytes, 46U, 40U, big_endian);
    write_u16(bytes, 48U, shnum, big_endian);
    write_u16(bytes, 50U, shstrndx, big_endian);
}

void write_elf64_program(std::vector<std::uint8_t>& bytes, std::size_t offset,
                         std::uint32_t type, std::uint32_t flags, std::uint64_t file_offset,
                         std::uint64_t address, std::uint64_t file_size,
                         std::uint64_t memory_size, std::uint64_t alignment) {
    write_u32(bytes, offset, type, false);
    write_u32(bytes, offset + 4U, flags, false);
    write_u64(bytes, offset + 8U, file_offset, false);
    write_u64(bytes, offset + 16U, address, false);
    write_u64(bytes, offset + 24U, address, false);
    write_u64(bytes, offset + 32U, file_size, false);
    write_u64(bytes, offset + 40U, memory_size, false);
    write_u64(bytes, offset + 48U, alignment, false);
}

void write_elf64_section(std::vector<std::uint8_t>& bytes, std::uint32_t index,
                         std::uint32_t name, std::uint32_t type, std::uint64_t flags,
                         std::uint64_t address, std::uint64_t file_offset,
                         std::uint64_t size, std::uint32_t link, std::uint32_t info,
                         std::uint64_t alignment, std::uint64_t entry_size) {
    const auto offset = rich_section_offset + static_cast<std::size_t>(index) * 64U;
    write_u32(bytes, offset, name, false);
    write_u32(bytes, offset + 4U, type, false);
    write_u64(bytes, offset + 8U, flags, false);
    write_u64(bytes, offset + 16U, address, false);
    write_u64(bytes, offset + 24U, file_offset, false);
    write_u64(bytes, offset + 32U, size, false);
    write_u32(bytes, offset + 40U, link, false);
    write_u32(bytes, offset + 44U, info, false);
    write_u64(bytes, offset + 48U, alignment, false);
    write_u64(bytes, offset + 56U, entry_size, false);
}

std::vector<std::uint8_t> make_rich_shared_elf64() {
    std::vector<std::uint8_t> bytes(rich_file_size, 0);
    write_elf64_header(bytes, 3U, 62U, false, rich_base + 0x200U,
                       rich_program_offset, rich_section_offset, 3U, 22U, 21U);
    write_elf64_program(bytes, rich_program_offset, 1U, 5U, 0U, rich_base,
                        rich_section_offset, rich_section_offset, 0x1000U);
    write_elf64_program(bytes, rich_program_offset + 56U, 2U, 6U,
                        rich_dynamic_offset, rich_base + rich_dynamic_offset,
                        rich_dynamic_size, rich_dynamic_size, 8U);
    write_elf64_program(bytes, rich_program_offset + 112U, 0x6474e550U, 4U,
                        rich_eh_frame_header_offset, rich_base + rich_eh_frame_header_offset,
                        16U, 16U, 4U);

    std::vector<std::uint8_t> names{0};
    const auto text_name = append_name(names, ".text");
    const auto dynamic_name = append_name(names, ".dynamic");
    const auto dynstr_name = append_name(names, ".dynstr");
    const auto dynsym_name = append_name(names, ".dynsym");
    const auto rela_name = append_name(names, ".rela.plt");
    const auto got_name = append_name(names, ".got.plt");
    const auto plt_name = append_name(names, ".plt");
    const auto init_name = append_name(names, ".init_array");
    const auto fini_name = append_name(names, ".fini_array");
    const auto note_name = append_name(names, ".note.gnu.build-id");
    const auto eh_frame_name = append_name(names, ".eh_frame");
    const auto eh_frame_header_name = append_name(names, ".eh_frame_hdr");
    const auto exception_name = append_name(names, ".gcc_except_table");
    const auto debug_link_name = append_name(names, ".gnu_debuglink");
    const auto debug_altlink_name = append_name(names, ".gnu_debugaltlink");
    const auto debug_info_name = append_name(names, ".debug_info");
    const auto debug_types_name = append_name(names, ".debug_types");
    const auto debug_names_name = append_name(names, ".debug_names");
    const auto strtab_name = append_name(names, ".strtab");
    const auto symtab_name = append_name(names, ".symtab");
    const auto shstrtab_name = append_name(names, ".shstrtab");
    require(names.size() <= rich_section_offset - rich_shstrtab_offset,
            "fixture section-name table exceeds its reserved range");
    write_bytes(bytes, rich_shstrtab_offset, names);

    write_elf64_section(bytes, 1U, static_cast<std::uint32_t>(text_name), 1U, 0x6U,
                        rich_base + 0x200U, 0x200U, 0x20U, 0U, 0U, 16U, 0U);
    write_elf64_section(bytes, 2U, static_cast<std::uint32_t>(dynamic_name), 6U, 0x3U,
                        rich_base + rich_dynamic_offset, rich_dynamic_offset,
                        rich_dynamic_size, 3U, 0U, 8U, 16U);
    write_elf64_section(bytes, 3U, static_cast<std::uint32_t>(dynstr_name), 3U, 0x2U,
                        rich_base + rich_dynstr_offset, rich_dynstr_offset, 18U,
                        0U, 0U, 1U, 0U);
    write_elf64_section(bytes, 4U, static_cast<std::uint32_t>(dynsym_name), 11U, 0x2U,
                        rich_base + rich_dynsym_offset, rich_dynsym_offset, 48U,
                        3U, 1U, 8U, 24U);
    write_elf64_section(bytes, 5U, static_cast<std::uint32_t>(rela_name), 4U, 0x2U,
                        rich_base + rich_rela_offset, rich_rela_offset, 24U,
                        4U, 6U, 8U, 24U);
    write_elf64_section(bytes, 6U, static_cast<std::uint32_t>(got_name), 1U, 0x3U,
                        rich_base + rich_got_offset, rich_got_offset, 24U,
                        0U, 0U, 8U, 8U);
    write_elf64_section(bytes, 7U, static_cast<std::uint32_t>(plt_name), 1U, 0x6U,
                        rich_base + rich_plt_offset, rich_plt_offset, 32U,
                        0U, 0U, 16U, 16U);
    write_elf64_section(bytes, 8U, static_cast<std::uint32_t>(init_name), 14U, 0x3U,
                        rich_base + rich_init_offset, rich_init_offset, 8U,
                        0U, 0U, 8U, 8U);
    write_elf64_section(bytes, 9U, static_cast<std::uint32_t>(fini_name), 15U, 0x3U,
                        rich_base + rich_fini_offset, rich_fini_offset, 8U,
                        0U, 0U, 8U, 8U);
    write_elf64_section(bytes, 10U, static_cast<std::uint32_t>(note_name), 7U, 0x2U,
                        rich_base + rich_note_offset, rich_note_offset, 20U,
                        0U, 0U, 4U, 0U);
    write_elf64_section(bytes, 11U, static_cast<std::uint32_t>(eh_frame_name), 1U, 0x2U,
                        rich_base + rich_eh_frame_offset, rich_eh_frame_offset, 16U,
                        0U, 0U, 4U, 0U);
    write_elf64_section(bytes, 12U, static_cast<std::uint32_t>(eh_frame_header_name), 1U, 0x2U,
                        rich_base + rich_eh_frame_header_offset, rich_eh_frame_header_offset,
                        16U, 0U, 0U, 4U, 0U);
    write_elf64_section(bytes, 13U, static_cast<std::uint32_t>(exception_name), 1U, 0x2U,
                        rich_base + rich_exception_offset, rich_exception_offset, 8U,
                        0U, 0U, 4U, 0U);
    write_elf64_section(bytes, 14U, static_cast<std::uint32_t>(debug_link_name), 1U, 0U,
                        0U, rich_debug_link_offset, 20U, 0U, 0U, 1U, 0U);
    write_elf64_section(bytes, 15U, static_cast<std::uint32_t>(debug_altlink_name), 1U, 0U,
                        0U, rich_debug_altlink_offset, 15U, 0U, 0U, 1U, 0U);
    write_elf64_section(bytes, 16U, static_cast<std::uint32_t>(debug_info_name), 1U, 0U,
                        0U, rich_debug_info_offset, 4U, 0U, 0U, 1U, 0U);
    write_elf64_section(bytes, 17U, static_cast<std::uint32_t>(debug_types_name), 1U, 0U,
                        0U, rich_debug_types_offset, 4U, 0U, 0U, 1U, 0U);
    write_elf64_section(bytes, 18U, static_cast<std::uint32_t>(debug_names_name), 1U, 0U,
                        0U, rich_debug_names_offset, 4U, 0U, 0U, 1U, 0U);
    write_elf64_section(bytes, 19U, static_cast<std::uint32_t>(strtab_name), 3U, 0U,
                        0U, rich_strtab_offset, 10U, 0U, 0U, 1U, 0U);
    write_elf64_section(bytes, 20U, static_cast<std::uint32_t>(symtab_name), 2U, 0U,
                        0U, rich_symtab_offset, 48U, 19U, 2U, 8U, 24U);
    write_elf64_section(bytes, 21U, static_cast<std::uint32_t>(shstrtab_name), 3U, 0U,
                        0U, rich_shstrtab_offset, names.size(), 0U, 0U, 1U, 0U);

    bytes[0x200U] = 0xc3U;
    write_bytes(bytes, rich_dynstr_offset,
                {0U, 'l', 'i', 'b', 'c', '.', 's', 'o', '.', '6', 0U,
                 't', 'a', 'r', 'g', 'e', 't', 0U});
    write_u32(bytes, rich_dynsym_offset + 24U, 11U, false);
    bytes[rich_dynsym_offset + 28U] = 0x12U;
    write_u16(bytes, rich_dynsym_offset + 30U, 0U, false);
    write_u64(bytes, rich_rela_offset, rich_base + rich_got_offset + 8U, false);
    write_u64(bytes, rich_rela_offset + 8U, (std::uint64_t{1} << 32U) | 7U, false);
    write_u64(bytes, rich_rela_offset + 16U, 0U, false);
    write_u64(bytes, rich_init_offset, rich_base + 0x200U, false);
    write_u64(bytes, rich_fini_offset, rich_base + 0x204U, false);
    write_u32(bytes, rich_note_offset, 4U, false);
    write_u32(bytes, rich_note_offset + 4U, 4U, false);
    write_u32(bytes, rich_note_offset + 8U, 3U, false);
    write_text(bytes, rich_note_offset + 12U, "GNU\0");
    write_text(bytes, rich_note_offset + 16U, "AiDA");
    write_text(bytes, rich_debug_link_offset, "module.debug\0");
    write_u32(bytes, rich_debug_link_offset + align4(13U), 0x12345678U, false);
    write_text(bytes, rich_debug_altlink_offset, "module.alt\0");
    write_bytes(bytes, rich_debug_altlink_offset + 11U, {0x01U, 0x02U, 0x03U, 0x04U});
    write_bytes(bytes, rich_debug_info_offset, {1U, 2U, 3U, 4U});
    write_bytes(bytes, rich_debug_types_offset, {5U, 6U, 7U, 8U});
    write_bytes(bytes, rich_debug_names_offset, {9U, 10U, 11U, 12U});
    write_bytes(bytes, rich_strtab_offset,
                {0U, 'l', 'o', 'c', 'a', 'l', '_', 'f', 'n', 0U});
    write_u32(bytes, rich_symtab_offset + 24U, 1U, false);
    bytes[rich_symtab_offset + 28U] = 0x02U;
    write_u16(bytes, rich_symtab_offset + 30U, 1U, false);
    write_u64(bytes, rich_symtab_offset + 32U, rich_base + 0x200U, false);
    write_u64(bytes, rich_symtab_offset + 40U, 4U, false);

    const std::array<std::pair<std::int64_t, std::uint64_t>, 13> dynamic_entries{{
        {1, 1U},
        {5, rich_base + rich_dynstr_offset},
        {10, 18U},
        {6, rich_base + rich_dynsym_offset},
        {11, 24U},
        {3, rich_base + rich_got_offset},
        {12, rich_base + 0x200U},
        {13, rich_base + 0x204U},
        {25, rich_base + rich_init_offset},
        {27, 8U},
        {26, rich_base + rich_fini_offset},
        {28, 8U},
        {0, 0U}}};
    for (std::size_t index = 0; index < dynamic_entries.size(); ++index) {
        const auto offset = rich_dynamic_offset + index * 16U;
        write_u64(bytes, offset, static_cast<std::uint64_t>(dynamic_entries[index].first), false);
        write_u64(bytes, offset + 8U, dynamic_entries[index].second, false);
    }
    return bytes;
}

std::vector<std::uint8_t> make_minimal_load_elf(bool is_64, bool big_endian,
                                                 std::uint16_t type, std::uint16_t machine) {
    const auto size = is_64 ? std::size_t{0x100U} : std::size_t{0x80U};
    const auto base = is_64 ? std::uint64_t{0x400000U} : std::uint64_t{0x10000U};
    std::vector<std::uint8_t> bytes(size, 0);
    if (is_64) {
        write_elf64_header(bytes, type, machine, big_endian,
                           type == 2U ? base : 0U, 64U, 0U, 1U, 0U, 0U);
        write_unsigned(bytes, 64U, 1U, 4U, big_endian);
        write_unsigned(bytes, 68U, 5U, 4U, big_endian);
        write_unsigned(bytes, 72U, 0U, 8U, big_endian);
        write_unsigned(bytes, 80U, base, 8U, big_endian);
        write_unsigned(bytes, 88U, base, 8U, big_endian);
        write_unsigned(bytes, 96U, size, 8U, big_endian);
        write_unsigned(bytes, 104U, size, 8U, big_endian);
        write_unsigned(bytes, 112U, 0x1000U, 8U, big_endian);
    } else {
        write_elf32_header(bytes, type, machine, big_endian,
                           type == 2U ? static_cast<std::uint32_t>(base) : 0U,
                           52U, 0U, 1U, 0U, 0U);
        write_unsigned(bytes, 52U, 1U, 4U, big_endian);
        write_unsigned(bytes, 56U, 0U, 4U, big_endian);
        write_unsigned(bytes, 60U, base, 4U, big_endian);
        write_unsigned(bytes, 64U, base, 4U, big_endian);
        write_unsigned(bytes, 68U, size, 4U, big_endian);
        write_unsigned(bytes, 72U, size, 4U, big_endian);
        write_unsigned(bytes, 76U, 5U, 4U, big_endian);
        write_unsigned(bytes, 80U, 0x1000U, 4U, big_endian);
    }
    return bytes;
}

std::vector<std::uint8_t> make_relocatable_elf32() {
    std::vector<std::uint8_t> bytes(0x180U, 0);
    write_elf32_header(bytes, 1U, 3U, false, 0U, 0U, 0x100U, 0U, 3U, 2U);
    const std::vector<std::uint8_t> names{0U, '.', 't', 'e', 'x', 't', 0U,
                                           '.', 's', 'h', 's', 't', 'r', 't', 'a', 'b', 0U};
    write_bytes(bytes, 0x70U, names);
    bytes[0x60U] = 0xc3U;
    const auto write_section = [&bytes](std::uint32_t index, std::uint32_t name,
                                        std::uint32_t type, std::uint32_t flags,
                                        std::uint32_t offset, std::uint32_t size,
                                        std::uint32_t alignment) {
        const auto base = std::size_t{0x100U} + static_cast<std::size_t>(index) * 40U;
        write_u32(bytes, base, name, false);
        write_u32(bytes, base + 4U, type, false);
        write_u32(bytes, base + 8U, flags, false);
        write_u32(bytes, base + 16U, offset, false);
        write_u32(bytes, base + 20U, size, false);
        write_u32(bytes, base + 32U, alignment, false);
    };
    write_section(1U, 1U, 1U, 0x6U, 0x60U, 4U, 4U);
    write_section(2U, 7U, 3U, 0U, 0x70U, static_cast<std::uint32_t>(names.size()), 1U);
    return bytes;
}

class fixture_file_t final {
public:
    explicit fixture_file_t(const std::vector<std::uint8_t>& bytes) {
        static std::atomic<std::uint64_t> sequence{0};
        const auto ordinal = sequence.fetch_add(1U, std::memory_order_relaxed);
        path_ = std::filesystem::temp_directory_path() /
                ("aida_elf_reader_" + std::to_string(ordinal) + ".elf");
        std::ofstream output(path_, std::ios::binary | std::ios::trunc);
        if (!output)
            throw std::runtime_error("ELF fixture open failed");
        output.write(reinterpret_cast<const char*>(bytes.data()),
                     static_cast<std::streamsize>(bytes.size()));
        output.flush();
        if (!output)
            throw std::runtime_error("ELF fixture write failed");
    }

    ~fixture_file_t() {
        std::error_code ignored;
        std::filesystem::remove(path_, ignored);
    }

    fixture_file_t(const fixture_file_t&) = delete;
    fixture_file_t& operator=(const fixture_file_t&) = delete;

    const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

class read_only_provider_t final : public byte_provider_t {
public:
    explicit read_only_provider_t(std::shared_ptr<const byte_provider_t> parent)
        : parent_(std::move(parent)), identity_(parent_->identity()) {}

    const byte_provider_identity_t& identity() const noexcept override { return identity_; }
    std::uint64_t size() const noexcept override { return parent_->size(); }
    std::uint64_t maximum_contiguous_lease(std::uint64_t offset) const noexcept override {
        return parent_->maximum_contiguous_lease(offset);
    }
    workspace_result_t<byte_view_t> lease(
        std::uint64_t offset, std::uint64_t size,
        const cancellation_token_t& cancel = {}) const override {
        ++lease_count_;
        return parent_->lease(offset, size, cancel);
    }

    std::uint64_t lease_count() const noexcept { return lease_count_; }

private:
    std::shared_ptr<const byte_provider_t> parent_;
    byte_provider_identity_t identity_;
    mutable std::uint64_t lease_count_ = 0;
};

elf_metadata_t read_fixture(const std::vector<std::uint8_t>& bytes,
                            const elf_metadata_reader_limits_t& limits = {}) {
    fixture_file_t fixture(bytes);
    auto provider = require_value(mapped_file_provider_t::open(fixture.path().u8string()),
                                  "ELF fixture provider open failed");
    return require_value(read_elf_metadata(*provider, limits), "ELF metadata read failed");
}

workspace_result_t<elf_metadata_t> read_fixture_result(
    const std::vector<std::uint8_t>& bytes,
    const elf_metadata_reader_limits_t& limits = {}) {
    fixture_file_t fixture(bytes);
    auto provider = mapped_file_provider_t::open(fixture.path().u8string());
    if (!provider)
        return workspace_result_t<elf_metadata_t>::failure(provider.error());
    return read_elf_metadata(*provider.value(), limits);
}

bool contains_symbol(const elf_metadata_t& metadata, std::string_view name,
                     elf_symbol_seed_source_t source, bool imported, bool local) {
    return std::any_of(metadata.symbol_seeds.begin(), metadata.symbol_seeds.end(),
                       [name, source, imported, local](const elf_symbol_seed_t& seed) {
                           return seed.name == name && seed.source == source &&
                                  seed.imported == imported && seed.local == local;
                       });
}

bool contains_type_seed(const elf_metadata_t& metadata, elf_type_seed_kind_t kind) {
    return std::any_of(metadata.type_seeds.begin(), metadata.type_seeds.end(),
                       [kind](const elf_type_seed_t& seed) { return seed.kind == kind; });
}

std::string normalized_signature(const elf_metadata_t& metadata) {
    std::string signature;
    const auto append = [&signature](const auto& value) {
        signature += std::to_string(static_cast<unsigned long long>(value));
        signature.push_back('|');
    };
    append(static_cast<std::uint8_t>(metadata.image.filetype));
    append(metadata.image.is_64bit ? 1U : 0U);
    append(static_cast<std::uint8_t>(metadata.image.endian));
    append(metadata.image.normalized.address_width_bits);
    append(metadata.image.normalized.image_base);
    append(metadata.image.normalized.image_size);
    append(metadata.image.sections.size());
    append(metadata.image.segments.size());
    append(metadata.image.relocations.size());
    for (const auto& seed : metadata.symbol_seeds) {
        append(static_cast<std::uint8_t>(seed.source));
        append(seed.table_section_index);
        append(seed.table_symbol_index);
        signature += seed.name;
        signature.push_back('|');
        append(seed.address ? seed.address->value : 0U);
        append(seed.imported ? 1U : 0U);
        append(seed.exported ? 1U : 0U);
    }
    for (const auto& link : metadata.debug_links) {
        append(static_cast<std::uint8_t>(link.kind));
        signature += link.path;
        signature.push_back('|');
        append(link.crc32.value_or(0U));
        signature += link.build_id_hex.value_or("");
        signature.push_back('|');
    }
    return signature;
}

void verify_rich_metadata() {
    const auto metadata = read_fixture(make_rich_shared_elf64());
    require(metadata.image.filetype == elf_filetype_t::shared && metadata.image.is_64bit &&
                metadata.image.endian == endian_t::little,
            "rich ELF class, endian, or file type drifted");
    require(metadata.image.segments.size() == 3U && metadata.image.sections.size() == 22U,
            "rich ELF program or section tables drifted");
    require(metadata.image.dynsym_symbols.size() == 2U &&
                metadata.image.symtab_symbols.size() == 2U,
            "rich ELF dynamic or local symbols were not retained");
    require(metadata.image.relocations.size() == 1U &&
                !metadata.image.plt_got_entries.empty(),
            "rich ELF relocations or PLT/GOT records were not retained");
    require(metadata.image.init_fini_entries.size() == 4U && metadata.image.notes.size() == 1U,
            "rich ELF init/fini or note records were not retained");
    require(metadata.image.needed_libraries == std::vector<std::string>{"libc.so.6"},
            "rich ELF needed library normalization drifted");
    require(contains_symbol(metadata, "target", elf_symbol_seed_source_t::dynamic_symbol_table,
                            true, false) &&
                contains_symbol(metadata, "local_fn", elf_symbol_seed_source_t::symbol_table,
                                false, true),
            "rich ELF symbol seeds lost dynamic or local provenance");
    require(contains_type_seed(metadata, elf_type_seed_kind_t::dwarf_info) &&
                contains_type_seed(metadata, elf_type_seed_kind_t::dwarf_types) &&
                contains_type_seed(metadata, elf_type_seed_kind_t::dwarf_names),
            "rich ELF type seeds lost DWARF sources");
    require(metadata.unwind_regions.size() == 3U && metadata.exception_regions.size() == 1U,
            "rich ELF unwind or exception regions drifted");
    require(metadata.debug_links.size() == 2U &&
                metadata.debug_links[0].kind == elf_debug_link_kind_t::gnu_debuglink &&
                metadata.debug_links[0].path == "module.debug" &&
                metadata.debug_links[0].crc32 == 0x12345678U &&
                metadata.debug_links[1].kind == elf_debug_link_kind_t::gnu_debugaltlink &&
                metadata.debug_links[1].path == "module.alt" &&
                metadata.debug_links[1].build_id_hex == "01020304",
            "rich ELF debug-link records drifted");
}

void verify_class_endian_and_object_variants() {
    const auto relocatable = read_fixture(make_relocatable_elf32());
    require(relocatable.image.filetype == elf_filetype_t::relocatable &&
                !relocatable.image.is_64bit && relocatable.image.endian == endian_t::little,
            "ELF32 little-endian relocatable fixture was not recognized");

    const auto executable = read_fixture(make_minimal_load_elf(true, false, 2U, 62U));
    require(executable.image.filetype == elf_filetype_t::executable &&
                executable.image.is_64bit && executable.image.endian == endian_t::little,
            "ELF64 little-endian executable fixture was not recognized");

    const auto shared32_big = read_fixture(make_minimal_load_elf(false, true, 3U, 8U));
    require(shared32_big.image.filetype == elf_filetype_t::shared &&
                !shared32_big.image.is_64bit && shared32_big.image.endian == endian_t::big,
            "ELF32 big-endian shared fixture was not recognized");

    const auto shared64_big = read_fixture(make_minimal_load_elf(true, true, 3U, 21U));
    require(shared64_big.image.filetype == elf_filetype_t::shared &&
                shared64_big.image.is_64bit && shared64_big.image.endian == endian_t::big,
            "ELF64 big-endian shared fixture was not recognized");
}

void verify_malformed_bounds_and_output_limits() {
    auto malformed_bounds = make_rich_shared_elf64();
    write_u64(malformed_bounds, 40U, rich_file_size - 8U, false);
    const auto bounds_result = read_fixture_result(malformed_bounds);
    require(!bounds_result && bounds_result.error().code == workspace_error_code_t::malformed_image,
            "out-of-bounds ELF section table was accepted");

    auto malformed_link = make_rich_shared_elf64();
    std::fill(malformed_link.begin() + static_cast<std::ptrdiff_t>(rich_debug_link_offset),
              malformed_link.begin() + static_cast<std::ptrdiff_t>(rich_debug_link_offset + 20U),
              static_cast<std::uint8_t>('x'));
    const auto link_result = read_fixture_result(malformed_link);
    require(!link_result && link_result.error().code == workspace_error_code_t::malformed_image &&
                link_result.error().phase == "elf_reader",
            "unterminated GNU debug-link was accepted");

    elf_metadata_reader_limits_t limits;
    limits.max_symbol_seeds = 1U;
    const auto limited = read_fixture_result(make_rich_shared_elf64(), limits);
    require(!limited && limited.error().code == workspace_error_code_t::limit_exceeded &&
                limited.error().phase == "elf_reader",
            "ELF reader symbol seed cap was not enforced");
}

void verify_stable_normalized_records() {
    const auto bytes = make_rich_shared_elf64();
    const auto first = read_fixture(bytes);
    const auto second = read_fixture(bytes);
    require(normalized_signature(first) == normalized_signature(second),
            "ELF metadata normalization was not stable");
}

void verify_metadata_only_provider_surface() {
    fixture_file_t fixture(make_rich_shared_elf64());
    auto mapped = require_value(mapped_file_provider_t::open(fixture.path().u8string()),
                                "metadata-only fixture provider open failed");
    read_only_provider_t provider(mapped);
    const auto metadata = require_value(read_elf_metadata(provider),
                                        "metadata-only ELF read failed");
    require(provider.lease_count() != 0U && metadata.image.normalized.format == format_id_t::elf,
            "ELF reader did not complete through the static byte-provider surface");
}

}

void run_elf_reader_harness() {
    verify_rich_metadata();
    verify_class_endian_and_object_variants();
    verify_malformed_bounds_and_output_limits();
    verify_stable_normalized_records();
    verify_metadata_only_provider_surface();
}

}

int main() {
    try {
        aida::analysis::c03_test::run_elf_reader_harness();
        std::cout << "elf_reader_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        std::cerr << error.what() << '\n';
        return 1;
    }
}
