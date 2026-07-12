#include "macho_reader_harness.hpp"

#include "../../src/core/analysis/readers/macho_reader.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace aida::analysis::c03_test {
namespace {

using readers::macho_bind_stream_kind_t;
using readers::macho_container_kind_t;
using readers::macho_file_kind_t;
using readers::read_macho_metadata;

void require(bool condition, const char* message) {
    if (!condition)
        throw std::runtime_error(message);
}

void put_u32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value, bool little = true) {
    require(offset <= bytes.size() && bytes.size() - offset >= 4U, "fixture u32 write overflow");
    if (little) {
        bytes[offset] = static_cast<std::uint8_t>(value);
        bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
        bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 16U);
        bytes[offset + 3U] = static_cast<std::uint8_t>(value >> 24U);
    } else {
        bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
        bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
        bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
        bytes[offset + 3U] = static_cast<std::uint8_t>(value);
    }
}

void put_u64(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint64_t value, bool little = true) {
    require(offset <= bytes.size() && bytes.size() - offset >= 8U, "fixture u64 write overflow");
    for (std::size_t index = 0; index < 8U; ++index) {
        const auto shift = little ? index * 8U : (7U - index) * 8U;
        bytes[offset + index] = static_cast<std::uint8_t>(value >> shift);
    }
}

void put_name(std::vector<std::uint8_t>& bytes, std::size_t offset, const std::string& name) {
    require(name.size() <= 16U, "fixture Mach-O name is too long");
    require(offset <= bytes.size() && bytes.size() - offset >= 16U, "fixture name write overflow");
    std::copy(name.begin(), name.end(), bytes.begin() + static_cast<std::ptrdiff_t>(offset));
}

void put_section(std::vector<std::uint8_t>& bytes, std::size_t offset, const std::string& name,
                 const std::string& segment, std::uint64_t address, std::uint64_t size,
                 std::uint32_t file_offset, std::uint32_t relocation_offset,
                 std::uint32_t relocation_count) {
    put_name(bytes, offset, name);
    put_name(bytes, offset + 16U, segment);
    put_u64(bytes, offset + 32U, address);
    put_u64(bytes, offset + 40U, size);
    put_u32(bytes, offset + 48U, file_offset);
    put_u32(bytes, offset + 52U, 3U);
    put_u32(bytes, offset + 56U, relocation_offset);
    put_u32(bytes, offset + 60U, relocation_count);
}

std::vector<std::uint8_t> make_thin_arm64_fixture() {
    constexpr std::size_t k_size = 0x600U;
    constexpr std::size_t k_segment_size = 72U + 5U * 80U;
    constexpr std::size_t k_symtab_size = 24U;
    constexpr std::size_t k_dylib_size = 56U;
    constexpr std::size_t k_dyld_size = 48U;
    constexpr std::size_t k_linkedit_size = 16U;
    std::vector<std::uint8_t> bytes(k_size, 0U);
    put_u32(bytes, 0U, 0xfeedfacfU);
    put_u32(bytes, 4U, 0x0100000cU);
    put_u32(bytes, 8U, 0U);
    put_u32(bytes, 12U, 0x6U);
    put_u32(bytes, 16U, 6U);
    put_u32(bytes, 20U, static_cast<std::uint32_t>(k_segment_size + k_symtab_size + k_dylib_size +
                                                    k_dyld_size + k_linkedit_size + k_linkedit_size));
    put_u32(bytes, 24U, 0x200000U);
    put_u32(bytes, 28U, 0U);

    std::size_t command = 32U;
    put_u32(bytes, command, 0x19U);
    put_u32(bytes, command + 4U, static_cast<std::uint32_t>(k_segment_size));
    put_name(bytes, command + 8U, "__TEXT");
    put_u64(bytes, command + 24U, 0x100000000ULL);
    put_u64(bytes, command + 32U, 0x1000U);
    put_u64(bytes, command + 40U, 0U);
    put_u64(bytes, command + 48U, k_size);
    put_u32(bytes, command + 56U, 7U);
    put_u32(bytes, command + 60U, 5U);
    put_u32(bytes, command + 64U, 5U);
    put_u32(bytes, command + 68U, 0U);
    const auto section = command + 72U;
    put_section(bytes, section, "__text", "__TEXT", 0x100000100ULL, 0x40U, 0x100U, 0x480U, 1U);
    put_section(bytes, section + 80U, "__objc_classlist", "__DATA", 0x100000200ULL, 8U, 0x200U, 0U, 0U);
    put_section(bytes, section + 160U, "__swift5_types", "__TEXT", 0x100000220ULL, 8U, 0x210U, 0U, 0U);
    put_section(bytes, section + 240U, "__compact_unwind", "__LD", 0x100000300ULL, 0x20U, 0x230U, 0U, 0U);
    put_section(bytes, section + 320U, "__eh_frame", "__TEXT", 0x100000340ULL, 0x10U, 0x260U, 0U, 0U);
    put_u64(bytes, 0x230U, 0x100000100ULL);
    command += k_segment_size;

    put_u32(bytes, command, 0x2U);
    put_u32(bytes, command + 4U, static_cast<std::uint32_t>(k_symtab_size));
    put_u32(bytes, command + 8U, 0x300U);
    put_u32(bytes, command + 12U, 1U);
    put_u32(bytes, command + 16U, 0x320U);
    put_u32(bytes, command + 20U, 0x20U);
    command += k_symtab_size;

    put_u32(bytes, command, 0xcU);
    put_u32(bytes, command + 4U, static_cast<std::uint32_t>(k_dylib_size));
    put_u32(bytes, command + 8U, 24U);
    put_u32(bytes, command + 12U, 7U);
    put_u32(bytes, command + 16U, 0x10000U);
    put_u32(bytes, command + 20U, 0x10000U);
    const std::string dylib = "/usr/lib/libFixture.dylib";
    std::copy(dylib.begin(), dylib.end(), bytes.begin() + static_cast<std::ptrdiff_t>(command + 24U));
    command += k_dylib_size;

    put_u32(bytes, command, 0x80000022U);
    put_u32(bytes, command + 4U, static_cast<std::uint32_t>(k_dyld_size));
    put_u32(bytes, command + 8U, 0x360U);
    put_u32(bytes, command + 12U, 6U);
    put_u32(bytes, command + 16U, 0x370U);
    put_u32(bytes, command + 20U, 13U);
    put_u32(bytes, command + 40U, 0x390U);
    put_u32(bytes, command + 44U, 12U);
    command += k_dyld_size;

    put_u32(bytes, command, 0x33U);
    put_u32(bytes, command + 4U, static_cast<std::uint32_t>(k_linkedit_size));
    put_u32(bytes, command + 8U, 0x390U);
    put_u32(bytes, command + 12U, 12U);
    command += k_linkedit_size;

    put_u32(bytes, command, 0x1dU);
    put_u32(bytes, command + 4U, static_cast<std::uint32_t>(k_linkedit_size));
    put_u32(bytes, command + 8U, 0x3b0U);
    put_u32(bytes, command + 12U, 28U);

    put_u32(bytes, 0x300U, 1U);
    bytes[0x304U] = 0x0fU;
    bytes[0x305U] = 1U;
    put_u64(bytes, 0x308U, 0x100000100ULL);
    const std::string symbol = "_fixture";
    std::copy(symbol.begin(), symbol.end(), bytes.begin() + 0x321U);

    const std::vector<std::uint8_t> rebase{0x20U, 0x80U, 0x01U, 0x11U, 0x51U, 0x00U};
    std::copy(rebase.begin(), rebase.end(), bytes.begin() + 0x360U);
    const std::vector<std::uint8_t> bind{0x70U, 0x80U, 0x01U, 0x11U, 0x40U, 'p', 'u', 't', 's', 0U, 0x51U, 0x90U, 0x00U};
    std::copy(bind.begin(), bind.end(), bytes.begin() + 0x370U);
    const std::vector<std::uint8_t> export_trie{0U, 1U, 'f', 'o', 'o', 0U, 7U, 2U, 0U, 0x80U, 0x02U, 0U};
    std::copy(export_trie.begin(), export_trie.end(), bytes.begin() + 0x390U);

    put_u32(bytes, 0x3b0U, 0xfade0cc0U, false);
    put_u32(bytes, 0x3b4U, 28U, false);
    put_u32(bytes, 0x3b8U, 1U, false);
    put_u32(bytes, 0x3bcU, 0U, false);
    put_u32(bytes, 0x3c0U, 20U, false);
    put_u32(bytes, 0x3c4U, 0xfade0c02U, false);
    put_u32(bytes, 0x3c8U, 8U, false);

    put_u32(bytes, 0x480U, 0x20U);
    put_u32(bytes, 0x484U, 0x20000000U);
    return bytes;
}

std::vector<std::uint8_t> make_big_endian_x64_fixture() {
    std::vector<std::uint8_t> bytes(32U, 0U);
    put_u32(bytes, 0U, 0xfeedfacfU, false);
    put_u32(bytes, 4U, 0x01000007U, false);
    put_u32(bytes, 8U, 0U, false);
    put_u32(bytes, 12U, 0x2U, false);
    return bytes;
}

std::vector<std::uint8_t> make_minimal_little_endian_fixture(std::uint32_t file_type) {
    std::vector<std::uint8_t> bytes(28U, 0U);
    put_u32(bytes, 0U, 0xfeedfaceU);
    put_u32(bytes, 4U, 7U);
    put_u32(bytes, 8U, 3U);
    put_u32(bytes, 12U, file_type);
    return bytes;
}

std::vector<std::uint8_t> make_fat_fixture() {
    const auto arm64 = make_thin_arm64_fixture();
    const auto x64 = make_big_endian_x64_fixture();
    std::vector<std::uint8_t> bytes(0x800U + x64.size(), 0U);
    put_u32(bytes, 0U, 0xcafebabeU, false);
    put_u32(bytes, 4U, 2U, false);
    put_u32(bytes, 8U, 0x0100000cU, false);
    put_u32(bytes, 12U, 0U, false);
    put_u32(bytes, 16U, 0x100U, false);
    put_u32(bytes, 20U, static_cast<std::uint32_t>(arm64.size()), false);
    put_u32(bytes, 24U, 8U, false);
    put_u32(bytes, 28U, 0x01000007U, false);
    put_u32(bytes, 32U, 0U, false);
    put_u32(bytes, 36U, 0x800U, false);
    put_u32(bytes, 40U, static_cast<std::uint32_t>(x64.size()), false);
    put_u32(bytes, 44U, 5U, false);
    std::copy(arm64.begin(), arm64.end(), bytes.begin() + 0x100U);
    std::copy(x64.begin(), x64.end(), bytes.begin() + 0x800U);
    return bytes;
}

std::vector<std::uint8_t> make_archive_fixture() {
    const auto member = make_thin_arm64_fixture();
    std::vector<std::uint8_t> bytes;
    const std::string magic = "!<arch>\n";
    bytes.insert(bytes.end(), magic.begin(), magic.end());
    std::vector<std::uint8_t> header(60U, static_cast<std::uint8_t>(' '));
    const std::string name = "fixture.o/";
    std::copy(name.begin(), name.end(), header.begin());
    const auto size = std::to_string(member.size());
    std::copy(size.begin(), size.end(), header.begin() + 48U);
    header[58U] = '`';
    header[59U] = '\n';
    bytes.insert(bytes.end(), header.begin(), header.end());
    bytes.insert(bytes.end(), member.begin(), member.end());
    if ((member.size() & 1U) != 0U)
        bytes.push_back('\n');
    return bytes;
}

void verify_thin_metadata() {
    const auto result = read_macho_metadata(make_thin_arm64_fixture());
    require(result.has_value(), "thin Mach-O fixture was rejected");
    const auto& document = result.value();
    require(document.container_kind == macho_container_kind_t::thin && document.slices.size() == 1U,
            "thin Mach-O container shape drifted");
    const auto& image = document.slices.front();
    require(image.file_kind == macho_file_kind_t::dylib && image.identity.is_64_bit,
            "thin Mach-O file kind or width drifted");
    require(image.load_commands.size() == 6U && image.segments.size() == 1U &&
                image.segments.front().sections.size() == 5U,
            "thin Mach-O load command or segment metadata drifted");
    require(image.dylibs.size() == 1U && image.dylibs.front().path == "/usr/lib/libFixture.dylib",
            "Mach-O dylib metadata drifted");
    require(image.symbols.size() == 1U && image.symbols.front().name == "_fixture",
            "Mach-O symbol metadata drifted");
    require(image.rebases.size() == 1U && image.bindings.size() == 1U &&
                image.bindings.front().stream == macho_bind_stream_kind_t::regular &&
                image.bindings.front().symbol == "puts",
            "Mach-O bind or rebase metadata drifted");
    require(image.exports.size() == 1U && image.exports.front().name == "foo" &&
                image.exports.front().address == 0x100U,
            "Mach-O export metadata drifted");
    require(image.relocations.size() == 1U && image.relocations.front().section_index.has_value() &&
                *image.relocations.front().section_index == 0U,
            "Mach-O relocation metadata drifted");
    require(image.unwind.size() == 1U && image.unwind.front().function_address == 0x100000100ULL &&
                image.exceptions.size() == 1U,
            "Mach-O unwind or exception metadata drifted");
    require(image.metadata_seeds.size() == 2U, "Objective-C or Swift metadata seeds were not retained");
    require(image.code_signature.present && image.code_signature.parsed &&
                image.code_signature.command_offset == 0x288U && image.code_signature.slots.size() == 1U &&
                !image.code_signature.verified &&
                !image.code_signature.trusted,
            "Mach-O code signature metadata claimed trust or lost read-only detail");
}

void verify_fat_and_endian_identity() {
    const auto fixture = make_fat_fixture();
    const auto first = read_macho_metadata(fixture);
    const auto second = read_macho_metadata(fixture);
    require(first.has_value() && second.has_value(), "fat Mach-O fixture was rejected");
    require(first.value().container_kind == macho_container_kind_t::fat && first.value().slices.size() == 2U,
            "fat Mach-O slices were not retained");
    require(first.value().slices[0].identity.stable_key() == second.value().slices[0].identity.stable_key() &&
                first.value().slices[1].identity.stable_key() == second.value().slices[1].identity.stable_key(),
            "fat Mach-O slice identities were not stable");
    require(first.value().differential_records() == second.value().differential_records(),
            "Mach-O normalized differential records were not stable");
    require(first.value().slices[1].identity.endian == endian_t::big &&
                first.value().slices[1].file_kind == macho_file_kind_t::executable,
            "big-endian Mach-O slice metadata drifted");
}

void verify_archive_metadata() {
    const auto result = read_macho_metadata(make_archive_fixture());
    require(result.has_value(), "Mach-O archive fixture was rejected");
    require(result.value().container_kind == macho_container_kind_t::archive &&
                result.value().archive_members.size() == 1U && result.value().archive_members.front().embedded &&
                result.value().archive_members.front().mach_metadata_available &&
                result.value().slices.size() == 1U &&
                result.value().slices.front().identity.archive_member_ordinal.has_value() &&
                *result.value().slices.front().identity.archive_member_ordinal == 0U,
            "Mach-O archive member provenance drifted");
}

void verify_object_and_bundle_metadata() {
    const auto object = read_macho_metadata(make_minimal_little_endian_fixture(0x1U));
    const auto bundle = read_macho_metadata(make_minimal_little_endian_fixture(0x8U));
    require(object.has_value() && bundle.has_value() && object.value().slices.size() == 1U &&
                bundle.value().slices.size() == 1U &&
                object.value().slices.front().file_kind == macho_file_kind_t::object &&
                bundle.value().slices.front().file_kind == macho_file_kind_t::bundle,
            "Mach-O object or bundle metadata drifted");
}

void verify_malformed_rejection() {
    auto invalid_command = make_thin_arm64_fixture();
    put_u32(invalid_command, 36U, 4U);
    const auto invalid_command_result = read_macho_metadata(invalid_command);
    require(!invalid_command_result.has_value() &&
                invalid_command_result.error().code == workspace_error_code_t::malformed_image,
            "invalid Mach-O load command was accepted");

    auto invalid_fat = make_fat_fixture();
    put_u32(invalid_fat, 16U, 0xffffff00U, false);
    const auto invalid_fat_result = read_macho_metadata(invalid_fat);
    require(!invalid_fat_result.has_value() &&
                invalid_fat_result.error().code == workspace_error_code_t::out_of_range,
            "out-of-range fat Mach-O slice was accepted");

    readers::macho_reader_limits_t limits;
    limits.max_input_bytes = 32U;
    const auto bounded_result = read_macho_metadata(make_thin_arm64_fixture(), limits);
    require(!bounded_result.has_value() && bounded_result.error().code == workspace_error_code_t::limit_exceeded,
            "Mach-O input bound was not enforced");
}

}

void run_macho_reader_harness() {
    verify_thin_metadata();
    verify_fat_and_endian_identity();
    verify_archive_metadata();
    verify_object_and_bundle_metadata();
    verify_malformed_rejection();
}

}

int main() {
    try {
        aida::analysis::c03_test::run_macho_reader_harness();
        std::cout << "macho_reader_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
