#include "fixture_materializer.hpp"

#include "evidence_hash.hpp"
#include "managed_fixture_fidelity/managed_fixture_fidelity.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>

namespace aida::analysis::c03
{
namespace
{
    using bytes_t = std::vector<std::uint8_t>;

    struct materialization_error_t : std::runtime_error
    {
        using std::runtime_error::runtime_error;
    };

    void require(bool condition, std::string message)
    {
        if (!condition)
            throw materialization_error_t(std::move(message));
    }

    void ensure(bytes_t& bytes, std::size_t offset, std::size_t count)
    {
        require(offset <= bytes.size() && count <= bytes.size() - offset,
            "fixture write exceeds the allocated artifact");
    }

    void put_unsigned(bytes_t& bytes, std::size_t offset, std::uint64_t value,
        std::size_t width, bool big_endian)
    {
        ensure(bytes, offset, width);
        for (std::size_t index = 0; index < width; ++index) {
            const auto shift = big_endian ? (width - index - 1) * 8 : index * 8;
            bytes[offset + index] = static_cast<std::uint8_t>(value >> shift);
        }
    }

    void append_unsigned(bytes_t& bytes, std::uint64_t value, std::size_t width,
        bool big_endian)
    {
        const auto offset = bytes.size();
        bytes.resize(offset + width);
        put_unsigned(bytes, offset, value, width, big_endian);
    }

    void put_text(bytes_t& bytes, std::size_t offset, std::string_view text)
    {
        ensure(bytes, offset, text.size());
        std::copy(text.begin(), text.end(), bytes.begin() + static_cast<std::ptrdiff_t>(offset));
    }

    void append_text(bytes_t& bytes, std::string_view text)
    {
        bytes.insert(bytes.end(), text.begin(), text.end());
    }

    std::uint16_t pe_machine(std::string_view architecture)
    {
        if (architecture == "x86") return 0x014c;
        if (architecture == "x64") return 0x8664;
        if (architecture == "arm") return 0x01c4;
        if (architecture == "aarch64") return 0xaa64;
        if (architecture == "arm64ec") return 0xa641;
        if (architecture == "arm64x") return 0xa64e;
        throw materialization_error_t("unsupported PE/COFF architecture");
    }

    std::string_view semantic_profile(const json& recipe)
    {
        require(recipe.contains("semantic_profile") &&
            recipe.at("semantic_profile").is_string(),
            "fixture recipe omits its semantic profile");
        const auto& value = recipe.at("semantic_profile").get_ref<const std::string&>();
        require(value == "native_conditional_dispatch" ||
            value == "native_conditional_add" || value == "native_sum" ||
            value == "native_zero" || value == "managed_cli" ||
            value == "managed_cli_readytorun" || value == "jvm_fixture" ||
            value == "dalvik_fixture", "fixture recipe semantic profile is unsupported");
        return value;
    }

    std::string_view native_symbol(const json& recipe)
    {
        const auto profile = semantic_profile(recipe);
        require(profile == "native_conditional_dispatch" ||
            profile == "native_conditional_add" || profile == "native_sum",
            "native symbol requested for a non-native semantic profile");
        return profile == "native_sum" ? std::string_view{"fixture_sum"} :
            std::string_view{"fixture_add"};
    }

    bytes_t conditional_add_code(std::string_view architecture)
    {
        if (architecture == "x86")
            return {0x8b, 0x44, 0x24, 0x04, 0x85, 0xc0, 0x79, 0x09,
                    0x8b, 0x4c, 0x24, 0x08, 0x29, 0xc1, 0x89, 0xc8,
                    0xc3, 0x03, 0x44, 0x24, 0x08, 0xc3};
        if (architecture == "x64")
            return {0x8b, 0xc1, 0x85, 0xc9, 0x79, 0x05, 0x8b, 0xc2,
                    0x2b, 0xc1, 0xc3, 0x8d, 0x04, 0x11, 0xc3};
        throw materialization_error_t(
            "conditional-add semantic profile requires x86 or x64");
    }

    bytes_t make_cli_metadata()
    {
        bytes_t strings{0};
        const auto add_string = [&](std::string_view value) {
            require(strings.size() <= (std::numeric_limits<std::uint16_t>::max)(),
                "CLI string heap exceeds compact fixture indexing");
            const auto index = static_cast<std::uint16_t>(strings.size());
            append_text(strings, value);
            strings.push_back(0);
            return index;
        };
        const auto module_name = add_string("ManagedFixture.dll");
        const auto module_type = add_string("<Module>");
        const auto fixture_type = add_string("ManagedFixture");
        const auto fixture_namespace = add_string("AiDA.C03.Corpus");
        const auto add_name = add_string("Add");
        const auto divide_name = add_string("GuardedDivide");
        const auto object_type = add_string("Object");
        const auto divide_by_zero_type = add_string("DivideByZeroException");
        const auto system_namespace = add_string("System");
        const auto runtime_assembly = add_string("mscorlib");
        const auto constructor_name = add_string(".ctor");
        const auto left_name = add_string("left");
        const auto right_name = add_string("right");
        const auto value_name = add_string("value");
        const auto divisor_name = add_string("divisor");

        bytes_t blob{0, 5, 0, 2, 8, 8, 8, 3, 0x20, 0, 1};
        bytes_t guid{
            0x83, 0xa9, 0x7e, 0x42, 0x5a, 0x17, 0x3b, 0xe6,
            0x84, 0x67, 0xd2, 0x4d, 0x10, 0x51, 0x39, 0xc0};
        bytes_t tables;
        const std::uint64_t valid_mask = (1ULL << 0U) | (1ULL << 1U) |
            (1ULL << 2U) | (1ULL << 6U) | (1ULL << 8U) | (1ULL << 10U) |
            (1ULL << 32U) | (1ULL << 35U);
        append_unsigned(tables, 0, 4, false);
        append_unsigned(tables, 2, 1, false);
        append_unsigned(tables, 0, 1, false);
        append_unsigned(tables, 0, 1, false);
        append_unsigned(tables, 1, 1, false);
        append_unsigned(tables, valid_mask, 8, false);
        append_unsigned(tables, 0, 8, false);
        append_unsigned(tables, 1, 4, false);
        append_unsigned(tables, 2, 4, false);
        append_unsigned(tables, 2, 4, false);
        append_unsigned(tables, 2, 4, false);
        append_unsigned(tables, 4, 4, false);
        append_unsigned(tables, 1, 4, false);
        append_unsigned(tables, 1, 4, false);
        append_unsigned(tables, 1, 4, false);

        append_unsigned(tables, 0, 2, false);
        append_unsigned(tables, module_name, 2, false);
        append_unsigned(tables, 1, 2, false);
        append_unsigned(tables, 0, 2, false);
        append_unsigned(tables, 0, 2, false);

        append_unsigned(tables, 6, 2, false);
        append_unsigned(tables, object_type, 2, false);
        append_unsigned(tables, system_namespace, 2, false);
        append_unsigned(tables, 6, 2, false);
        append_unsigned(tables, divide_by_zero_type, 2, false);
        append_unsigned(tables, system_namespace, 2, false);

        append_unsigned(tables, 0, 4, false);
        append_unsigned(tables, module_type, 2, false);
        append_unsigned(tables, 0, 2, false);
        append_unsigned(tables, 0, 2, false);
        append_unsigned(tables, 1, 2, false);
        append_unsigned(tables, 1, 2, false);
        append_unsigned(tables, 0x00100101U, 4, false);
        append_unsigned(tables, fixture_type, 2, false);
        append_unsigned(tables, fixture_namespace, 2, false);
        append_unsigned(tables, 5, 2, false);
        append_unsigned(tables, 1, 2, false);
        append_unsigned(tables, 1, 2, false);

        append_unsigned(tables, 0x1080, 4, false);
        append_unsigned(tables, 0, 2, false);
        append_unsigned(tables, 0x0096, 2, false);
        append_unsigned(tables, add_name, 2, false);
        append_unsigned(tables, 1, 2, false);
        append_unsigned(tables, 1, 2, false);
        append_unsigned(tables, 0x10a0, 4, false);
        append_unsigned(tables, 0, 2, false);
        append_unsigned(tables, 0x0096, 2, false);
        append_unsigned(tables, divide_name, 2, false);
        append_unsigned(tables, 1, 2, false);
        append_unsigned(tables, 3, 2, false);

        append_unsigned(tables, 0, 2, false);
        append_unsigned(tables, 1, 2, false);
        append_unsigned(tables, left_name, 2, false);
        append_unsigned(tables, 0, 2, false);
        append_unsigned(tables, 2, 2, false);
        append_unsigned(tables, right_name, 2, false);
        append_unsigned(tables, 0, 2, false);
        append_unsigned(tables, 1, 2, false);
        append_unsigned(tables, value_name, 2, false);
        append_unsigned(tables, 0, 2, false);
        append_unsigned(tables, 2, 2, false);
        append_unsigned(tables, divisor_name, 2, false);

        append_unsigned(tables, 17, 2, false);
        append_unsigned(tables, constructor_name, 2, false);
        append_unsigned(tables, 7, 2, false);

        append_unsigned(tables, 0x8004, 4, false);
        append_unsigned(tables, 1, 2, false);
        append_unsigned(tables, 0, 2, false);
        append_unsigned(tables, 0, 2, false);
        append_unsigned(tables, 0, 2, false);
        append_unsigned(tables, 0, 4, false);
        append_unsigned(tables, 0, 2, false);
        append_unsigned(tables, fixture_type, 2, false);
        append_unsigned(tables, 0, 2, false);

        append_unsigned(tables, 4, 2, false);
        append_unsigned(tables, 0, 2, false);
        append_unsigned(tables, 0, 2, false);
        append_unsigned(tables, 0, 2, false);
        append_unsigned(tables, 0, 4, false);
        append_unsigned(tables, 0, 2, false);
        append_unsigned(tables, runtime_assembly, 2, false);
        append_unsigned(tables, 0, 2, false);
        append_unsigned(tables, 0, 2, false);

        constexpr std::string_view version("v4.0.30319\0\0", 12);
        constexpr std::array<std::string_view, 4> stream_names{
            "#~", "#Strings", "#Blob", "#GUID"};
        const std::array<const bytes_t*, 4> streams{
            &tables, &strings, &blob, &guid};
        const auto padded = [](std::size_t value) {
            return (value + 3U) & ~std::size_t{3U};
        };
        std::size_t data_offset = 16U + padded(version.size()) + 4U;
        for (const auto name : stream_names)
            data_offset += 8U + padded(name.size() + 1U);
        std::array<std::size_t, 4> stream_offsets{};
        auto cursor = data_offset;
        for (std::size_t index = 0; index < streams.size(); ++index) {
            stream_offsets[index] = cursor;
            cursor = padded(cursor + streams[index]->size());
        }

        bytes_t metadata;
        append_unsigned(metadata, 0x424a5342, 4, false);
        append_unsigned(metadata, 1, 2, false);
        append_unsigned(metadata, 1, 2, false);
        append_unsigned(metadata, 0, 4, false);
        append_unsigned(metadata, version.size(), 4, false);
        append_text(metadata, version);
        metadata.resize(16U + padded(version.size()), 0);
        append_unsigned(metadata, 0, 2, false);
        append_unsigned(metadata, stream_names.size(), 2, false);
        for (std::size_t index = 0; index < streams.size(); ++index) {
            append_unsigned(metadata, stream_offsets[index], 4, false);
            append_unsigned(metadata, streams[index]->size(), 4, false);
            append_text(metadata, stream_names[index]);
            metadata.push_back(0);
            metadata.resize(padded(metadata.size()), 0);
        }
        require(metadata.size() == data_offset,
            "CLI metadata stream headers are inconsistent");
        for (std::size_t index = 0; index < streams.size(); ++index) {
            require(metadata.size() == stream_offsets[index],
                "CLI metadata stream offset is inconsistent");
            metadata.insert(metadata.end(), streams[index]->begin(), streams[index]->end());
            metadata.resize(padded(metadata.size()), 0);
        }
        require(metadata.size() <= 0x680U,
            "CLI metadata streams overlap the ReadyToRun metadata range");
        return metadata;
    }

    bytes_t native_code(std::string_view architecture, std::string_view mode,
        std::string_view endian, bool windows_x64 = false)
    {
        if (architecture == "x86")
            return {0x8b, 0x44, 0x24, 0x04, 0x03, 0x44, 0x24, 0x08, 0xc3};
        if (architecture == "x64")
            return windows_x64 ? bytes_t{0x8d, 0x04, 0x11, 0xc3} :
                bytes_t{0x8d, 0x04, 0x37, 0xc3};
        if (architecture == "arm" && mode == "thumb")
            return {0x40, 0x18, 0x70, 0x47};
        if (architecture == "arm")
            return endian == "big" ? bytes_t{0xe0, 0x80, 0x00, 0x01, 0xe1, 0x2f, 0xff, 0x1e} :
                bytes_t{0x01, 0x00, 0x80, 0xe0, 0x1e, 0xff, 0x2f, 0xe1};
        if (architecture == "aarch64" || architecture == "arm64ec" || architecture == "arm64x")
            return endian == "big" ? bytes_t{0x0b, 0x01, 0x00, 0x00, 0xd6, 0x5f, 0x03, 0xc0} :
                bytes_t{0x00, 0x00, 0x01, 0x0b, 0xc0, 0x03, 0x5f, 0xd6};
        if (architecture == "mips")
            return endian == "big" ? bytes_t{0x00, 0x85, 0x10, 0x21, 0x03, 0xe0, 0x00, 0x08,
                                               0x00, 0x00, 0x00, 0x00} :
                bytes_t{0x21, 0x10, 0x85, 0x00, 0x08, 0x00, 0xe0, 0x03,
                        0x00, 0x00, 0x00, 0x00};
        if (architecture == "ppc")
            return endian == "big" ? bytes_t{0x7c, 0x63, 0x22, 0x14, 0x4e, 0x80, 0x00, 0x20} :
                bytes_t{0x14, 0x22, 0x63, 0x7c, 0x20, 0x00, 0x80, 0x4e};
        if (architecture == "riscv")
            return {0x33, 0x05, 0xb5, 0x00, 0x67, 0x80, 0x00, 0x00};
        throw materialization_error_t("unsupported native code architecture");
    }

    bytes_t native_fragment_code(std::string_view architecture, std::string_view mode,
        std::string_view endian)
    {
        if (architecture == "x86" || architecture == "x64")
            return {0x31, 0xc0, 0xc3};
        if (architecture == "arm" && mode == "thumb")
            return {0x00, 0x20, 0x70, 0x47};
        if (architecture == "arm")
            return endian == "big" ? bytes_t{0xe3, 0xa0, 0x00, 0x00, 0xe1, 0x2f, 0xff, 0x1e} :
                bytes_t{0x00, 0x00, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1};
        if (architecture == "aarch64")
            return endian == "big" ? bytes_t{0xd2, 0x80, 0x00, 0x00, 0xd6, 0x5f, 0x03, 0xc0} :
                bytes_t{0x00, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6};
        if (architecture == "mips")
            return endian == "big" ? bytes_t{0x24, 0x02, 0x00, 0x00, 0x03, 0xe0, 0x00, 0x08,
                                               0x00, 0x00, 0x00, 0x00} :
                bytes_t{0x00, 0x00, 0x02, 0x24, 0x08, 0x00, 0xe0, 0x03,
                        0x00, 0x00, 0x00, 0x00};
        if (architecture == "ppc")
            return endian == "big" ? bytes_t{0x38, 0x60, 0x00, 0x00, 0x4e, 0x80, 0x00, 0x20} :
                bytes_t{0x00, 0x00, 0x60, 0x38, 0x20, 0x00, 0x80, 0x4e};
        if (architecture == "riscv")
            return {0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00};
        throw materialization_error_t("unsupported raw-code architecture");
    }

    bytes_t make_pe(const json& recipe)
    {
        const auto architecture = recipe.at("architecture").get<std::string>();
        const auto mode = recipe.at("mode").get<std::string>();
        const auto profile = semantic_profile(recipe);
        const bool is_64 = mode == "64" || architecture == "x64" || architecture == "aarch64" ||
            architecture == "arm64ec" || architecture == "arm64x";
        const bool managed = recipe.value("managed", false);
        const bool ready_to_run = recipe.value("ready_to_run", false);
        if (managed) {
            require(profile == (ready_to_run ? "managed_cli_readytorun" :
                "managed_cli"),
                "managed PE semantic profile disagrees with its ReadyToRun identity");
        } else {
            require(profile == "native_conditional_dispatch" ||
                profile == "native_conditional_add" || profile == "native_sum",
                "native PE semantic profile is invalid");
        }
        const std::size_t optional_size = is_64 ? 0xf0 : 0xe0;
        const std::size_t optional = 0x98;
        const std::size_t section = optional + optional_size;
        const std::size_t raw_offset = managed ? 0x1000U : 0x200U;
        const std::size_t raw_size = managed ? 0x2000U : 0x600U;
        bytes_t bytes(raw_offset + raw_size, 0);
        put_text(bytes, 0, "MZ");
        put_unsigned(bytes, 0x3c, 0x80, 4, false);
        put_text(bytes, 0x80, "PE\0\0");
        put_unsigned(bytes, 0x84, pe_machine(architecture), 2, false);
        put_unsigned(bytes, 0x86, 1, 2, false);
        put_unsigned(bytes, 0x88, 0x5f3759df, 4, false);
        put_unsigned(bytes, 0x94, optional_size, 2, false);
        put_unsigned(bytes, 0x96, managed ? 0x2022 : 0x0022, 2, false);
        put_unsigned(bytes, optional, is_64 ? 0x20b : 0x10b, 2, false);
        put_unsigned(bytes, optional + 4, raw_size, 4, false);
        put_unsigned(bytes, optional + 16,
            !managed || ready_to_run ? 0x1000 : 0, 4, false);
        put_unsigned(bytes, optional + 20, 0x1000, 4, false);
        if (is_64)
            put_unsigned(bytes, optional + 24, 0x140000000ULL, 8, false);
        else {
            put_unsigned(bytes, optional + 24, 0x1000, 4, false);
            put_unsigned(bytes, optional + 28, 0x400000, 4, false);
        }
        put_unsigned(bytes, optional + 32, 0x1000, 4, false);
        put_unsigned(bytes, optional + 36, 0x200, 4, false);
        put_unsigned(bytes, optional + 56, managed ? 0x3000 : 0x2000, 4, false);
        put_unsigned(bytes, optional + 60, 0x200, 4, false);
        put_unsigned(bytes, optional + 68, 3, 2, false);
        const auto directory_count = is_64 ? optional + 108 : optional + 92;
        const auto directories = is_64 ? optional + 112 : optional + 96;
        put_unsigned(bytes, directory_count, 16, 4, false);
        if (managed) {
            put_unsigned(bytes, directories + 14 * 8, 0x1100, 4, false);
            put_unsigned(bytes, directories + 14 * 8 + 4, 72, 4, false);
        }
        put_text(bytes, section, ".text");
        put_unsigned(bytes, section + 8, raw_size, 4, false);
        put_unsigned(bytes, section + 12, 0x1000, 4, false);
        put_unsigned(bytes, section + 16, raw_size, 4, false);
        put_unsigned(bytes, section + 20, raw_offset, 4, false);
        put_unsigned(bytes, section + 36, 0x60000020, 4, false);
        bytes_t code;
        if (!managed) {
            code = profile == "native_conditional_dispatch" ||
                    profile == "native_conditional_add" ?
                conditional_add_code(architecture) :
                native_code(architecture == "arm64ec" || architecture == "arm64x" ?
                    "aarch64" : architecture, mode, "little", true);
        } else if (ready_to_run) {
            code = conditional_add_code("x64");
        }
        if (!code.empty())
            std::copy(code.begin(), code.end(),
                bytes.begin() + static_cast<std::ptrdiff_t>(raw_offset));
        if (!managed && profile == "native_conditional_dispatch") {
            const bytes_t dispatch{
                0x8b, 0x44, 0x24, 0x04, 0x83, 0xf8, 0x00, 0x74, 0x08,
                0x83, 0xf8, 0x01, 0x74, 0x10, 0x31, 0xc0, 0xc3,
                0x6a, 0x02, 0x6a, 0x01, 0xe8, 0xc6, 0xff, 0xff, 0xff,
                0x83, 0xc4, 0x08, 0xc3, 0x6a, 0x02, 0x6a, 0xff,
                0xe8, 0xb9, 0xff, 0xff, 0xff, 0x83, 0xc4, 0x08, 0xc3};
            std::copy(dispatch.begin(), dispatch.end(),
                bytes.begin() + static_cast<std::ptrdiff_t>(raw_offset + 0x20U));
        }
        if (!managed) {
            constexpr std::uint32_t export_rva = 0x1200U;
            constexpr std::size_t export_offset = 0x400U;
            const bool two_exports = profile == "native_conditional_dispatch";
            const std::uint32_t export_count = two_exports ? 2U : 1U;
            put_unsigned(bytes, directories, export_rva, 4, false);
            put_unsigned(bytes, directories + 4, 0x100U, 4, false);
            put_unsigned(bytes, export_offset + 12, 0x1240U, 4, false);
            put_unsigned(bytes, export_offset + 16, 1, 4, false);
            put_unsigned(bytes, export_offset + 20, export_count, 4, false);
            put_unsigned(bytes, export_offset + 24, export_count, 4, false);
            put_unsigned(bytes, export_offset + 28, 0x1260U, 4, false);
            put_unsigned(bytes, export_offset + 32, 0x1270U, 4, false);
            put_unsigned(bytes, export_offset + 36, 0x1280U, 4, false);
            put_text(bytes, 0x440U, "fixture.exe");
            put_unsigned(bytes, 0x460U, 0x1000U, 4, false);
            put_unsigned(bytes, 0x470U, 0x1290U, 4, false);
            put_unsigned(bytes, 0x480U, 0, 2, false);
            put_text(bytes, 0x490U, native_symbol(recipe));
            if (two_exports) {
                put_unsigned(bytes, 0x464U, 0x1020U, 4, false);
                put_unsigned(bytes, 0x474U, 0x129cU, 4, false);
                put_unsigned(bytes, 0x482U, 1, 2, false);
                put_text(bytes, 0x49cU, "fixture_dispatch");
            }
        }
        if (managed) {
            constexpr std::size_t method_offset = 0x1080U;
            constexpr std::size_t divide_method_offset = 0x10a0U;
            constexpr std::size_t cli_offset = 0x1100U;
            constexpr std::size_t metadata_offset = 0x1180U;
            const auto metadata = make_cli_metadata();
            const bytes_t add_method_body{
                0x32, 0x02, 0x16, 0x2f, 0x04, 0x03, 0x02,
                0x59, 0x2a, 0x02, 0x03, 0x58, 0x2a};
            const bytes_t divide_method_body{
                0x36, 0x03, 0x2d, 0x06, 0x73, 0x01, 0x00,
                0x00, 0x0a, 0x7a, 0x02, 0x03, 0x5b, 0x2a};
            std::copy(add_method_body.begin(), add_method_body.end(),
                bytes.begin() + static_cast<std::ptrdiff_t>(method_offset));
            std::copy(divide_method_body.begin(), divide_method_body.end(),
                bytes.begin() + static_cast<std::ptrdiff_t>(divide_method_offset));
            put_unsigned(bytes, cli_offset, 72, 4, false);
            put_unsigned(bytes, cli_offset + 4, 2, 2, false);
            put_unsigned(bytes, cli_offset + 6, 5, 2, false);
            put_unsigned(bytes, cli_offset + 8, metadata_offset, 4, false);
            put_unsigned(bytes, cli_offset + 12, metadata.size(), 4, false);
            put_unsigned(bytes, cli_offset + 16, 1, 4, false);
            put_unsigned(bytes, cli_offset + 20, 0x06000001, 4, false);
            std::copy(metadata.begin(), metadata.end(),
                bytes.begin() + static_cast<std::ptrdiff_t>(metadata_offset));
            if (ready_to_run) {
                constexpr std::size_t ready_offset = 0x1800U;
                constexpr std::size_t compiler_offset = 0x1820U;
                put_unsigned(bytes, cli_offset + 64, ready_offset, 4, false);
                put_unsigned(bytes, cli_offset + 68, 28, 4, false);
                put_text(bytes, ready_offset, "RTR\0");
                put_unsigned(bytes, ready_offset + 4, 8, 2, false);
                put_unsigned(bytes, ready_offset + 6, 0, 2, false);
                put_unsigned(bytes, ready_offset + 8, 0, 4, false);
                put_unsigned(bytes, ready_offset + 12, 1, 2, false);
                put_unsigned(bytes, ready_offset + 14, 12, 1, false);
                put_unsigned(bytes, ready_offset + 15, 0, 1, false);
                put_unsigned(bytes, ready_offset + 16, 100, 4, false);
                put_unsigned(bytes, ready_offset + 20, compiler_offset, 4, false);
                put_unsigned(bytes, ready_offset + 24, 9, 4, false);
                put_text(bytes, compiler_offset, "AiDA.C03\0");
            }
        }
        return bytes;
    }

    bytes_t make_coff(const json& recipe)
    {
        constexpr std::size_t raw_offset = 0x50U;
        constexpr std::size_t symbol_offset = 0x60U;
        constexpr std::size_t string_table_offset = symbol_offset + 18U;
        require(semantic_profile(recipe) == "native_sum",
            "COFF fixture semantic profile must describe fixture_sum");
        const auto symbol_name = native_symbol(recipe);
        bytes_t bytes(0x90, 0);
        put_unsigned(bytes, 0, pe_machine(recipe.at("architecture").get<std::string>()), 2, false);
        put_unsigned(bytes, 2, 1, 2, false);
        put_unsigned(bytes, 4, 0x10203040, 4, false);
        put_unsigned(bytes, 8, symbol_offset, 4, false);
        put_unsigned(bytes, 12, 1, 4, false);
        put_text(bytes, 20, ".text");
        const auto code = native_code(recipe.at("architecture").get<std::string>(),
            recipe.at("mode").get<std::string>(), recipe.at("endian").get<std::string>(), true);
        put_unsigned(bytes, 28, code.size(), 4, false);
        put_unsigned(bytes, 36, code.size(), 4, false);
        put_unsigned(bytes, 40, raw_offset, 4, false);
        put_unsigned(bytes, 56, 0x60000020, 4, false);
        std::copy(code.begin(), code.end(), bytes.begin() + raw_offset);
        put_unsigned(bytes, symbol_offset + 4, 4, 4, false);
        put_unsigned(bytes, symbol_offset + 8, 0, 4, false);
        put_unsigned(bytes, symbol_offset + 12, 1, 2, false);
        put_unsigned(bytes, symbol_offset + 14, 0x20, 2, false);
        bytes[symbol_offset + 16] = 2;
        put_unsigned(bytes, string_table_offset, 4U + symbol_name.size() + 1U, 4, false);
        put_text(bytes, string_table_offset + 4U, symbol_name);
        return bytes;
    }

    std::uint16_t elf_machine(std::string_view architecture, bool is_64)
    {
        if (architecture == "x86") return 3;
        if (architecture == "x64") return 62;
        if (architecture == "arm") return 40;
        if (architecture == "aarch64") return 183;
        if (architecture == "mips") return 8;
        if (architecture == "ppc") return is_64 ? 21 : 20;
        if (architecture == "riscv") return 243;
        throw materialization_error_t("unsupported ELF architecture");
    }

    bytes_t make_elf(const json& recipe)
    {
        require(semantic_profile(recipe) == "native_sum",
            "ELF fixture semantic profile must describe fixture_sum");
        const bool is_64 = recipe.at("mode") == "64";
        const bool big = recipe.at("endian") == "big";
        const auto file_kind = recipe.value("file_kind", std::string("executable"));
        const std::uint16_t type = file_kind == "relocatable" ? 1 : file_kind == "shared" ? 3 : 2;
        const auto machine = elf_machine(recipe.at("architecture").get<std::string>(), is_64);
        const auto header_size = is_64 ? 64U : 52U;
        const auto program_size = is_64 ? 56U : 32U;
        const auto section_size = is_64 ? 64U : 40U;
        const auto code_offset = std::size_t{0x100};
        const auto section_names_offset = std::size_t{0x120};
        const auto symbol_names_offset = std::size_t{0x150};
        const auto symbols_offset = std::size_t{0x170};
        const auto section_offset = std::size_t{0x200};
        const auto symbol_size = is_64 ? 24U : 16U;
        constexpr std::size_t section_name_size = 33U;
        constexpr std::size_t symbol_name_size = 13U;
        bytes_t bytes(0x400, 0);
        put_text(bytes, 0, "\x7f" "ELF");
        bytes[4] = is_64 ? 2 : 1;
        bytes[5] = big ? 2 : 1;
        bytes[6] = 1;
        put_unsigned(bytes, 16, type, 2, big);
        put_unsigned(bytes, 18, machine, 2, big);
        put_unsigned(bytes, 20, 1, 4, big);
        const auto base = is_64 ? 0x400000ULL : 0x10000ULL;
        if (is_64) {
            put_unsigned(bytes, 24, type == 1 ? 0 : base + code_offset, 8, big);
            put_unsigned(bytes, 32, type == 1 ? 0 : header_size, 8, big);
            put_unsigned(bytes, 40, section_offset, 8, big);
            put_unsigned(bytes, 52, header_size, 2, big);
            put_unsigned(bytes, 54, program_size, 2, big);
            put_unsigned(bytes, 56, type == 1 ? 0 : 1, 2, big);
            put_unsigned(bytes, 58, section_size, 2, big);
            put_unsigned(bytes, 60, 5, 2, big);
            put_unsigned(bytes, 62, 2, 2, big);
            if (type != 1) {
                put_unsigned(bytes, 64, 1, 4, big);
                put_unsigned(bytes, 68, 5, 4, big);
                put_unsigned(bytes, 72, 0, 8, big);
                put_unsigned(bytes, 80, base, 8, big);
                put_unsigned(bytes, 88, base, 8, big);
                put_unsigned(bytes, 96, bytes.size(), 8, big);
                put_unsigned(bytes, 104, bytes.size(), 8, big);
                put_unsigned(bytes, 112, 0x1000, 8, big);
            }
        } else {
            put_unsigned(bytes, 24, type == 1 ? 0 : base + code_offset, 4, big);
            put_unsigned(bytes, 28, type == 1 ? 0 : header_size, 4, big);
            put_unsigned(bytes, 32, section_offset, 4, big);
            put_unsigned(bytes, 40, header_size, 2, big);
            put_unsigned(bytes, 42, program_size, 2, big);
            put_unsigned(bytes, 44, type == 1 ? 0 : 1, 2, big);
            put_unsigned(bytes, 46, 40, 2, big);
            put_unsigned(bytes, 48, 5, 2, big);
            put_unsigned(bytes, 50, 2, 2, big);
            if (type != 1) {
                put_unsigned(bytes, 52, 1, 4, big);
                put_unsigned(bytes, 56, 0, 4, big);
                put_unsigned(bytes, 60, base, 4, big);
                put_unsigned(bytes, 64, base, 4, big);
                put_unsigned(bytes, 68, bytes.size(), 4, big);
                put_unsigned(bytes, 72, bytes.size(), 4, big);
                put_unsigned(bytes, 76, 5, 4, big);
                put_unsigned(bytes, 80, 0x1000, 4, big);
            }
        }
        const auto code = native_code(recipe.at("architecture").get<std::string>(),
            recipe.at("mode").get<std::string>(), recipe.at("endian").get<std::string>());
        std::copy(code.begin(), code.end(), bytes.begin() + static_cast<std::ptrdiff_t>(code_offset));
        put_text(bytes, section_names_offset + 1U, ".text");
        put_text(bytes, section_names_offset + 7U, ".shstrtab");
        put_text(bytes, section_names_offset + 17U, ".strtab");
        put_text(bytes, section_names_offset + 25U, ".symtab");
        put_text(bytes, symbol_names_offset + 1U, native_symbol(recipe));
        const auto symbol = symbols_offset + symbol_size;
        put_unsigned(bytes, symbol, 1, 4, big);
        if (is_64) {
            bytes[symbol + 4U] = 0x12U;
            put_unsigned(bytes, symbol + 6U, 1, 2, big);
            put_unsigned(bytes, symbol + 8U, type == 1 ? 0 : base + code_offset, 8, big);
            put_unsigned(bytes, symbol + 16U, code.size(), 8, big);
        } else {
            put_unsigned(bytes, symbol + 4U, type == 1 ? 0 : base + code_offset, 4, big);
            put_unsigned(bytes, symbol + 8U, code.size(), 4, big);
            bytes[symbol + 12U] = 0x12U;
            put_unsigned(bytes, symbol + 14U, 1, 2, big);
        }
        const auto write_section = [&](std::size_t index, std::uint32_t name,
                                       std::uint32_t section_type, std::uint64_t flags,
                                       std::uint64_t address, std::uint64_t offset,
                                       std::uint64_t size, std::uint32_t link,
                                       std::uint32_t info, std::uint64_t alignment,
                                       std::uint64_t entry_size) {
            const auto target = section_offset + index * section_size;
            put_unsigned(bytes, target, name, 4, big);
            put_unsigned(bytes, target + 4U, section_type, 4, big);
            if (is_64) {
                put_unsigned(bytes, target + 8U, flags, 8, big);
                put_unsigned(bytes, target + 16U, address, 8, big);
                put_unsigned(bytes, target + 24U, offset, 8, big);
                put_unsigned(bytes, target + 32U, size, 8, big);
                put_unsigned(bytes, target + 40U, link, 4, big);
                put_unsigned(bytes, target + 44U, info, 4, big);
                put_unsigned(bytes, target + 48U, alignment, 8, big);
                put_unsigned(bytes, target + 56U, entry_size, 8, big);
            } else {
                put_unsigned(bytes, target + 8U, flags, 4, big);
                put_unsigned(bytes, target + 12U, address, 4, big);
                put_unsigned(bytes, target + 16U, offset, 4, big);
                put_unsigned(bytes, target + 20U, size, 4, big);
                put_unsigned(bytes, target + 24U, link, 4, big);
                put_unsigned(bytes, target + 28U, info, 4, big);
                put_unsigned(bytes, target + 32U, alignment, 4, big);
                put_unsigned(bytes, target + 36U, entry_size, 4, big);
            }
        };
        write_section(1U, 1U, 1U, 6U, type == 1 ? 0 : base + code_offset,
            code_offset, code.size(), 0U, 0U, 4U, 0U);
        write_section(2U, 7U, 3U, 0U, 0U, section_names_offset,
            section_name_size, 0U, 0U, 1U, 0U);
        write_section(3U, 17U, 3U, 0U, 0U, symbol_names_offset,
            symbol_name_size, 0U, 0U, 1U, 0U);
        write_section(4U, 25U, 2U, 0U, 0U, symbols_offset,
            symbol_size * 2U, 3U, 1U, is_64 ? 8U : 4U, symbol_size);
        return bytes;
    }

    std::uint32_t macho_cpu(std::string_view architecture)
    {
        if (architecture == "x86") return 7;
        if (architecture == "x64") return 0x01000007;
        if (architecture == "arm") return 12;
        if (architecture == "aarch64") return 0x0100000c;
        if (architecture == "ppc") return 18;
        throw materialization_error_t("unsupported Mach-O architecture");
    }

    bytes_t make_macho_thin(const json& recipe)
    {
        require(semantic_profile(recipe) == "native_sum",
            "Mach-O fixture semantic profile must describe fixture_sum");
        const bool is_64 = recipe.at("mode") == "64";
        const bool big = recipe.at("endian") == "big";
        const bool object = recipe.value("file_kind", std::string("executable")) == "object";
        const auto header_size = is_64 ? 32U : 28U;
        const auto segment_size = is_64 ? 152U : 124U;
        const auto code_offset = is_64 ? 0x100U : 0xc0U;
        const auto symbol_offset = is_64 ? 0x110U : 0xd0U;
        const auto symbol_size = is_64 ? 16U : 12U;
        const auto string_offset = symbol_offset + symbol_size;
        const auto base = object ? 0ULL : (is_64 ? 0x100000000ULL : 0x1000ULL);
        const auto code = native_code(recipe.at("architecture").get<std::string>(),
            recipe.at("mode").get<std::string>(), recipe.at("endian").get<std::string>());
        bytes_t bytes(0x180, 0);
        put_unsigned(bytes, 0, is_64 ? 0xfeedfacf : 0xfeedface, 4, big);
        put_unsigned(bytes, 4, macho_cpu(recipe.at("architecture").get<std::string>()), 4, big);
        put_unsigned(bytes, 8, 0, 4, big);
        put_unsigned(bytes, 12, object ? 1 : 2, 4, big);
        put_unsigned(bytes, 16, 2, 4, big);
        put_unsigned(bytes, 20, segment_size + 24, 4, big);
        put_unsigned(bytes, 24, object ? 0 : 0x00200000, 4, big);
        if (is_64)
            put_unsigned(bytes, 28, 0, 4, big);
        const auto command = header_size;
        put_unsigned(bytes, command, is_64 ? 0x19 : 1, 4, big);
        put_unsigned(bytes, command + 4, segment_size, 4, big);
        put_text(bytes, command + 8, "__TEXT");
        if (is_64) {
            put_unsigned(bytes, command + 24, base, 8, big);
            put_unsigned(bytes, command + 32, code.size(), 8, big);
            put_unsigned(bytes, command + 40, code_offset, 8, big);
            put_unsigned(bytes, command + 48, code.size(), 8, big);
            put_unsigned(bytes, command + 56, 5, 4, big);
            put_unsigned(bytes, command + 60, 5, 4, big);
            put_unsigned(bytes, command + 64, 1, 4, big);
        } else {
            put_unsigned(bytes, command + 24, base, 4, big);
            put_unsigned(bytes, command + 28, code.size(), 4, big);
            put_unsigned(bytes, command + 32, code_offset, 4, big);
            put_unsigned(bytes, command + 36, code.size(), 4, big);
            put_unsigned(bytes, command + 40, 5, 4, big);
            put_unsigned(bytes, command + 44, 5, 4, big);
            put_unsigned(bytes, command + 48, 1, 4, big);
        }
        const auto section = command + (is_64 ? 72U : 56U);
        put_text(bytes, section, "__text");
        put_text(bytes, section + 16, "__TEXT");
        put_unsigned(bytes, section + 32, base, is_64 ? 8 : 4, big);
        if (is_64) {
            put_unsigned(bytes, section + 40, code.size(), 8, big);
            put_unsigned(bytes, section + 48, code_offset, 4, big);
            put_unsigned(bytes, section + 52, 2, 4, big);
            put_unsigned(bytes, section + 64, 0x80000400, 4, big);
        } else {
            put_unsigned(bytes, section + 36, code.size(), 4, big);
            put_unsigned(bytes, section + 40, code_offset, 4, big);
            put_unsigned(bytes, section + 44, 2, 4, big);
            put_unsigned(bytes, section + 56, 0x80000400, 4, big);
        }
        const auto symtab = command + segment_size;
        put_unsigned(bytes, symtab, 2, 4, big);
        put_unsigned(bytes, symtab + 4, 24, 4, big);
        put_unsigned(bytes, symtab + 8, symbol_offset, 4, big);
        put_unsigned(bytes, symtab + 12, 1, 4, big);
        put_unsigned(bytes, symtab + 16, string_offset, 4, big);
        put_unsigned(bytes, symtab + 20, 14, 4, big);
        put_unsigned(bytes, symbol_offset, 1, 4, big);
        bytes[symbol_offset + 4] = 0x0f;
        bytes[symbol_offset + 5] = 1;
        put_unsigned(bytes, symbol_offset + 6, 0, 2, big);
        put_unsigned(bytes, symbol_offset + 8, base, is_64 ? 8 : 4, big);
        put_text(bytes, string_offset + 1, "_fixture_sum");
        std::copy(code.begin(), code.end(), bytes.begin() + static_cast<std::ptrdiff_t>(code_offset));
        return bytes;
    }

    bytes_t make_macho_fat(const json& recipe)
    {
        json first = recipe;
        first["format"] = "macho_thin";
        first["architecture"] = "x64";
        first["mode"] = "64";
        first["endian"] = "little";
        json second = first;
        second["architecture"] = "aarch64";
        const auto x64 = make_macho_thin(first);
        const auto arm64 = make_macho_thin(second);
        bytes_t bytes(0x400 + arm64.size(), 0);
        put_unsigned(bytes, 0, 0xcafebabe, 4, true);
        put_unsigned(bytes, 4, 2, 4, true);
        put_unsigned(bytes, 8, macho_cpu("x64"), 4, true);
        put_unsigned(bytes, 16, 0x100, 4, true);
        put_unsigned(bytes, 20, x64.size(), 4, true);
        put_unsigned(bytes, 24, 8, 4, true);
        put_unsigned(bytes, 28, macho_cpu("aarch64"), 4, true);
        put_unsigned(bytes, 36, 0x400, 4, true);
        put_unsigned(bytes, 40, arm64.size(), 4, true);
        put_unsigned(bytes, 44, 8, 4, true);
        std::copy(x64.begin(), x64.end(), bytes.begin() + 0x100);
        std::copy(arm64.begin(), arm64.end(), bytes.begin() + 0x400);
        return bytes;
    }

    struct classfile_pool_t
    {
        bytes_t bytes;
        std::uint16_t count = 1U;

        std::uint16_t begin(std::uint8_t tag)
        {
            require(count != (std::numeric_limits<std::uint16_t>::max)(),
                "classfile constant pool is exhausted");
            bytes.push_back(tag);
            return count++;
        }

        std::uint16_t utf8(std::string_view value)
        {
            require(value.size() <= (std::numeric_limits<std::uint16_t>::max)(),
                "classfile UTF-8 constant exceeds the format limit");
            const auto index = begin(1U);
            append_unsigned(bytes, value.size(), 2U, true);
            append_text(bytes, value);
            return index;
        }

        std::uint16_t class_ref(std::uint16_t name)
        {
            const auto index = begin(7U);
            append_unsigned(bytes, name, 2U, true);
            return index;
        }

        std::uint16_t name_and_type(std::uint16_t name, std::uint16_t descriptor)
        {
            const auto index = begin(12U);
            append_unsigned(bytes, name, 2U, true);
            append_unsigned(bytes, descriptor, 2U, true);
            return index;
        }

        std::uint16_t member_ref(std::uint8_t tag, std::uint16_t owner,
            std::uint16_t identity)
        {
            const auto index = begin(tag);
            append_unsigned(bytes, owner, 2U, true);
            append_unsigned(bytes, identity, 2U, true);
            return index;
        }
    };

    void append_jvm_attribute(bytes_t& output, std::uint16_t name,
        const bytes_t& payload)
    {
        require(payload.size() <= (std::numeric_limits<std::uint32_t>::max)(),
            "classfile attribute exceeds the format limit");
        append_unsigned(output, name, 2U, true);
        append_unsigned(output, payload.size(), 4U, true);
        output.insert(output.end(), payload.begin(), payload.end());
    }

    bytes_t make_jvm_code(std::uint16_t max_stack, std::uint16_t max_locals,
        const bytes_t& code,
        const std::vector<std::array<std::uint16_t, 4>>& exceptions,
        const std::vector<std::array<std::uint16_t, 2>>& lines,
        const std::vector<std::array<std::uint16_t, 5>>& locals,
        std::uint16_t line_attribute, std::uint16_t local_attribute)
    {
        require(!code.empty() && code.size() <= 65535U &&
            exceptions.size() <= 65535U && lines.size() <= 65535U &&
            locals.size() <= 65535U, "classfile Code fixture exceeds bounded limits");
        bytes_t payload;
        append_unsigned(payload, max_stack, 2U, true);
        append_unsigned(payload, max_locals, 2U, true);
        append_unsigned(payload, code.size(), 4U, true);
        payload.insert(payload.end(), code.begin(), code.end());
        append_unsigned(payload, exceptions.size(), 2U, true);
        for (const auto& exception : exceptions) {
            for (const auto value : exception)
                append_unsigned(payload, value, 2U, true);
        }
        append_unsigned(payload, 2U, 2U, true);
        bytes_t line_payload;
        append_unsigned(line_payload, lines.size(), 2U, true);
        for (const auto& line : lines) {
            append_unsigned(line_payload, line[0], 2U, true);
            append_unsigned(line_payload, line[1], 2U, true);
        }
        append_jvm_attribute(payload, line_attribute, line_payload);
        bytes_t local_payload;
        append_unsigned(local_payload, locals.size(), 2U, true);
        for (const auto& local : locals) {
            for (const auto value : local)
                append_unsigned(local_payload, value, 2U, true);
        }
        append_jvm_attribute(payload, local_attribute, local_payload);
        return payload;
    }

    bytes_t make_classfile(const json& recipe)
    {
        require(semantic_profile(recipe) == "jvm_fixture",
            "classfile fixture semantic profile must describe the JVM source corpus");
        classfile_pool_t pool;
        const auto fixture_name = pool.utf8("aida/c03/corpus/Fixture");
        const auto fixture_class = pool.class_ref(fixture_name);
        const auto object_name = pool.utf8("java/lang/Object");
        const auto object_class = pool.class_ref(object_name);
        const auto arithmetic_name = pool.utf8("java/lang/ArithmeticException");
        const auto arithmetic_class = pool.class_ref(arithmetic_name);
        const auto fixture_descriptor = pool.utf8("Laida/c03/corpus/Fixture;");
        const auto integer_descriptor = pool.utf8("I");
        const auto void_descriptor = pool.utf8("()V");
        const auto binary_integer_descriptor = pool.utf8("(II)I");
        const auto constructor_name = pool.utf8("<init>");
        const auto add_name = pool.utf8("add");
        const auto divide_name = pool.utf8("guardedDivide");
        const auto bias_name = pool.utf8("bias");
        const auto code_name = pool.utf8("Code");
        const auto line_name = pool.utf8("LineNumberTable");
        const auto local_name = pool.utf8("LocalVariableTable");
        const auto source_name = pool.utf8("SourceFile");
        const auto source_value = pool.utf8("Fixture.java");
        const auto this_name = pool.utf8("this");
        const auto left_name = pool.utf8("left");
        const auto right_name = pool.utf8("right");
        const auto result_name = pool.utf8("result");
        const auto value_name = pool.utf8("value");
        const auto divisor_name = pool.utf8("divisor");
        const auto constructor_identity = pool.name_and_type(
            constructor_name, void_descriptor);
        const auto object_constructor = pool.member_ref(
            10U, object_class, constructor_identity);
        const auto arithmetic_constructor = pool.member_ref(
            10U, arithmetic_class, constructor_identity);
        const auto bias_identity = pool.name_and_type(bias_name, integer_descriptor);
        const auto bias_reference = pool.member_ref(9U, fixture_class, bias_identity);

        bytes_t output;
        append_unsigned(output, 0xcafebabeU, 4U, true);
        append_unsigned(output, 0U, 2U, true);
        append_unsigned(output, 49U, 2U, true);
        append_unsigned(output, pool.count, 2U, true);
        output.insert(output.end(), pool.bytes.begin(), pool.bytes.end());
        append_unsigned(output, 0x0031U, 2U, true);
        append_unsigned(output, fixture_class, 2U, true);
        append_unsigned(output, object_class, 2U, true);
        append_unsigned(output, 0U, 2U, true);
        append_unsigned(output, 1U, 2U, true);
        append_unsigned(output, 0x0019U, 2U, true);
        append_unsigned(output, bias_name, 2U, true);
        append_unsigned(output, integer_descriptor, 2U, true);
        append_unsigned(output, 0U, 2U, true);
        append_unsigned(output, 3U, 2U, true);

        const bytes_t constructor_code{0x2aU, 0xb7U,
            static_cast<std::uint8_t>(object_constructor >> 8U),
            static_cast<std::uint8_t>(object_constructor), 0xb1U};
        const auto constructor_payload = make_jvm_code(1U, 1U,
            constructor_code, {}, {{0U, 3U}},
            {{0U, static_cast<std::uint16_t>(constructor_code.size()),
              this_name, fixture_descriptor, 0U}}, line_name, local_name);
        append_unsigned(output, 0x0001U, 2U, true);
        append_unsigned(output, constructor_name, 2U, true);
        append_unsigned(output, void_descriptor, 2U, true);
        append_unsigned(output, 1U, 2U, true);
        append_jvm_attribute(output, code_name, constructor_payload);

        const bytes_t add_code{0x1aU, 0x1bU, 0x60U, 0xb2U,
            static_cast<std::uint8_t>(bias_reference >> 8U),
            static_cast<std::uint8_t>(bias_reference), 0x60U, 0x3dU,
            0x1cU, 0xacU, 0x57U, 0x03U, 0xacU};
        const auto add_payload = make_jvm_code(2U, 3U, add_code,
            {{0U, 10U, 10U, arithmetic_class}}, {{0U, 6U}, {10U, 9U}},
            {{0U, 13U, left_name, integer_descriptor, 0U},
             {0U, 13U, right_name, integer_descriptor, 1U},
             {7U, 3U, result_name, integer_descriptor, 2U}},
            line_name, local_name);
        append_unsigned(output, 0x0009U, 2U, true);
        append_unsigned(output, add_name, 2U, true);
        append_unsigned(output, binary_integer_descriptor, 2U, true);
        append_unsigned(output, 1U, 2U, true);
        append_jvm_attribute(output, code_name, add_payload);

        const bytes_t divide_code{0x1bU, 0x9aU, 0x00U, 0x0bU, 0xbbU,
            static_cast<std::uint8_t>(arithmetic_class >> 8U),
            static_cast<std::uint8_t>(arithmetic_class), 0x59U, 0xb7U,
            static_cast<std::uint8_t>(arithmetic_constructor >> 8U),
            static_cast<std::uint8_t>(arithmetic_constructor), 0xbfU,
            0x1aU, 0x1bU, 0x6cU, 0xacU};
        const auto divide_payload = make_jvm_code(2U, 2U, divide_code, {},
            {{0U, 15U}, {12U, 17U}},
            {{0U, 16U, value_name, integer_descriptor, 0U},
             {0U, 16U, divisor_name, integer_descriptor, 1U}},
            line_name, local_name);
        append_unsigned(output, 0x0009U, 2U, true);
        append_unsigned(output, divide_name, 2U, true);
        append_unsigned(output, binary_integer_descriptor, 2U, true);
        append_unsigned(output, 1U, 2U, true);
        append_jvm_attribute(output, code_name, divide_payload);

        append_unsigned(output, 1U, 2U, true);
        bytes_t source_payload;
        append_unsigned(source_payload, source_value, 2U, true);
        append_jvm_attribute(output, source_name, source_payload);
        return output;
    }

    void append_uleb128(bytes_t& output, std::uint32_t value)
    {
        do {
            auto byte = static_cast<std::uint8_t>(value & 0x7fU);
            value >>= 7U;
            if (value != 0U)
                byte |= 0x80U;
            output.push_back(byte);
        } while (value != 0U);
    }

    void align_four(bytes_t& output)
    {
        while ((output.size() & 3U) != 0U)
            output.push_back(0U);
    }

    std::uint32_t append_dex_code_item(bytes_t& output,
        std::uint16_t registers, std::uint16_t inputs, std::uint16_t outputs,
        std::uint32_t debug_offset, const std::vector<std::uint16_t>& instructions,
        bool with_handler)
    {
        align_four(output);
        require(output.size() <= (std::numeric_limits<std::uint32_t>::max)(),
            "DEX code offset exceeds the format limit");
        const auto offset = static_cast<std::uint32_t>(output.size());
        append_unsigned(output, registers, 2U, false);
        append_unsigned(output, inputs, 2U, false);
        append_unsigned(output, outputs, 2U, false);
        append_unsigned(output, with_handler ? 1U : 0U, 2U, false);
        append_unsigned(output, debug_offset, 4U, false);
        append_unsigned(output, instructions.size(), 4U, false);
        for (const auto instruction : instructions)
            append_unsigned(output, instruction, 2U, false);
        if (with_handler) {
            align_four(output);
            append_unsigned(output, 0U, 4U, false);
            append_unsigned(output, 3U, 2U, false);
            append_unsigned(output, 1U, 2U, false);
            append_uleb128(output, 1U);
            append_uleb128(output, 1U);
            append_uleb128(output, 2U);
            append_uleb128(output, 3U);
        }
        return offset;
    }

    bytes_t make_dex(const json& recipe)
    {
        require(semantic_profile(recipe) == "dalvik_fixture",
            "DEX fixture semantic profile must describe the Dalvik source corpus");
        const std::array<std::string_view, 14> strings{
            "<init>", "Fixture.smali", "I", "III", "Laida/c03/corpus/Fixture;",
            "Ljava/lang/ArithmeticException;", "Ljava/lang/Object;", "V",
            "add", "divisor", "guardedDivide", "left", "right", "value"};
        constexpr std::uint32_t string_ids_offset = 112U;
        constexpr std::uint32_t type_ids_offset = string_ids_offset + 14U * 4U;
        constexpr std::uint32_t proto_ids_offset = type_ids_offset + 5U * 4U;
        constexpr std::uint32_t method_ids_offset = proto_ids_offset + 2U * 12U;
        constexpr std::uint32_t class_defs_offset = method_ids_offset + 5U * 8U;
        constexpr std::uint32_t data_offset = class_defs_offset + 32U;
        bytes_t output(data_offset, 0U);
        put_text(output, 0U, std::string_view("dex\n035\0", 8U));
        put_unsigned(output, 36U, 112U, 4U, false);
        put_unsigned(output, 40U, 0x12345678U, 4U, false);
        put_unsigned(output, 56U, strings.size(), 4U, false);
        put_unsigned(output, 60U, string_ids_offset, 4U, false);
        put_unsigned(output, 64U, 5U, 4U, false);
        put_unsigned(output, 68U, type_ids_offset, 4U, false);
        put_unsigned(output, 72U, 2U, 4U, false);
        put_unsigned(output, 76U, proto_ids_offset, 4U, false);
        put_unsigned(output, 80U, 0U, 4U, false);
        put_unsigned(output, 84U, 0U, 4U, false);
        put_unsigned(output, 88U, 5U, 4U, false);
        put_unsigned(output, 92U, method_ids_offset, 4U, false);
        put_unsigned(output, 96U, 1U, 4U, false);
        put_unsigned(output, 100U, class_defs_offset, 4U, false);

        put_unsigned(output, type_ids_offset, 2U, 4U, false);
        put_unsigned(output, type_ids_offset + 4U, 4U, 4U, false);
        put_unsigned(output, type_ids_offset + 8U, 5U, 4U, false);
        put_unsigned(output, type_ids_offset + 12U, 6U, 4U, false);
        put_unsigned(output, type_ids_offset + 16U, 7U, 4U, false);
        put_unsigned(output, proto_ids_offset, 3U, 4U, false);
        put_unsigned(output, proto_ids_offset + 4U, 0U, 4U, false);
        put_unsigned(output, proto_ids_offset + 12U, 7U, 4U, false);
        put_unsigned(output, proto_ids_offset + 16U, 4U, 4U, false);

        const std::array<std::array<std::uint32_t, 3>, 5> methods{{
            {1U, 1U, 0U}, {1U, 0U, 8U}, {1U, 0U, 10U},
            {2U, 1U, 0U}, {3U, 1U, 0U}}};
        for (std::size_t index = 0; index < methods.size(); ++index) {
            const auto offset = method_ids_offset + index * 8U;
            put_unsigned(output, offset, methods[index][0], 2U, false);
            put_unsigned(output, offset + 2U, methods[index][1], 2U, false);
            put_unsigned(output, offset + 4U, methods[index][2], 4U, false);
        }

        const auto type_list_offset = static_cast<std::uint32_t>(output.size());
        append_unsigned(output, 2U, 4U, false);
        append_unsigned(output, 0U, 2U, false);
        append_unsigned(output, 0U, 2U, false);
        put_unsigned(output, proto_ids_offset + 8U, type_list_offset, 4U, false);

        std::array<std::uint32_t, 14> string_offsets{};
        const auto string_data_offset = static_cast<std::uint32_t>(output.size());
        for (std::size_t index = 0; index < strings.size(); ++index) {
            require(output.size() <= (std::numeric_limits<std::uint32_t>::max)(),
                "DEX string offset exceeds the format limit");
            string_offsets[index] = static_cast<std::uint32_t>(output.size());
            append_uleb128(output, static_cast<std::uint32_t>(strings[index].size()));
            append_text(output, strings[index]);
            output.push_back(0U);
            put_unsigned(output, string_ids_offset + index * 4U,
                string_offsets[index], 4U, false);
        }

        const auto debug_info_offset = static_cast<std::uint32_t>(output.size());
        const std::array<std::uint8_t, 4> constructor_debug{4U, 0U, 0x0eU, 0U};
        output.insert(output.end(), constructor_debug.begin(), constructor_debug.end());
        const auto add_debug_offset = static_cast<std::uint32_t>(output.size());
        const std::array<std::uint8_t, 9> add_debug{
            10U, 2U, 12U, 13U, 0x0eU, 1U, 3U, 0x0eU, 0U};
        output.insert(output.end(), add_debug.begin(), add_debug.end());
        const auto divide_debug_offset = static_cast<std::uint32_t>(output.size());
        const std::array<std::uint8_t, 9> divide_debug{
            23U, 2U, 14U, 10U, 0x0eU, 1U, 8U, 0x0eU, 0U};
        output.insert(output.end(), divide_debug.begin(), divide_debug.end());

        const auto constructor_code_offset = append_dex_code_item(output,
            1U, 1U, 1U, debug_info_offset,
            {0x1070U, 4U, 0U, 0x000eU}, false);
        const auto add_code_offset = append_dex_code_item(output,
            3U, 2U, 0U, add_debug_offset,
            {0x0090U, 0x0201U, 0x000fU, 0x0012U, 0x000fU}, true);
        const auto divide_code_offset = append_dex_code_item(output,
            3U, 2U, 1U, divide_debug_offset,
            {0x0239U, 8U, 0x0022U, 2U, 0x1070U, 3U, 0U,
             0x0027U, 0x0093U, 0x0201U, 0x000fU}, false);

        const auto class_data_offset = static_cast<std::uint32_t>(output.size());
        append_uleb128(output, 0U);
        append_uleb128(output, 0U);
        append_uleb128(output, 3U);
        append_uleb128(output, 0U);
        append_uleb128(output, 0U);
        append_uleb128(output, 0x10001U);
        append_uleb128(output, constructor_code_offset);
        append_uleb128(output, 1U);
        append_uleb128(output, 0x0009U);
        append_uleb128(output, add_code_offset);
        append_uleb128(output, 1U);
        append_uleb128(output, 0x0009U);
        append_uleb128(output, divide_code_offset);

        put_unsigned(output, class_defs_offset, 1U, 4U, false);
        put_unsigned(output, class_defs_offset + 4U, 0x0001U, 4U, false);
        put_unsigned(output, class_defs_offset + 8U, 3U, 4U, false);
        put_unsigned(output, class_defs_offset + 12U, 0U, 4U, false);
        put_unsigned(output, class_defs_offset + 16U, 1U, 4U, false);
        put_unsigned(output, class_defs_offset + 20U, 0U, 4U, false);
        put_unsigned(output, class_defs_offset + 24U, class_data_offset, 4U, false);
        put_unsigned(output, class_defs_offset + 28U, 0U, 4U, false);

        align_four(output);
        const auto map_offset = static_cast<std::uint32_t>(output.size());
        struct map_item_t { std::uint16_t type; std::uint32_t size; std::uint32_t offset; };
        const std::array<map_item_t, 12> items{{
            {0x0000U, 1U, 0U},
            {0x0001U, 14U, string_ids_offset},
            {0x0002U, 5U, type_ids_offset},
            {0x0003U, 2U, proto_ids_offset},
            {0x0005U, 5U, method_ids_offset},
            {0x0006U, 1U, class_defs_offset},
            {0x1001U, 1U, type_list_offset},
            {0x2002U, 14U, string_data_offset},
            {0x2003U, 3U, debug_info_offset},
            {0x2001U, 3U, constructor_code_offset},
            {0x2000U, 1U, class_data_offset},
            {0x1000U, 1U, map_offset}}};
        append_unsigned(output, items.size(), 4U, false);
        for (const auto& item : items) {
            append_unsigned(output, item.type, 2U, false);
            append_unsigned(output, 0U, 2U, false);
            append_unsigned(output, item.size, 4U, false);
            append_unsigned(output, item.offset, 4U, false);
        }
        require(output.size() <= (std::numeric_limits<std::uint32_t>::max)(),
            "DEX fixture exceeds the format size limit");
        put_unsigned(output, 32U, output.size(), 4U, false);
        put_unsigned(output, 52U, map_offset, 4U, false);
        put_unsigned(output, 104U, output.size() - data_offset, 4U, false);
        put_unsigned(output, 108U, data_offset, 4U, false);
        std::string integrity_error;
        require(seal_c03_dex(output, integrity_error), integrity_error);
        return output;
    }

    std::uint32_t crc32(const bytes_t& bytes)
    {
        std::uint32_t crc = 0xffffffffU;
        for (const auto byte : bytes) {
            crc ^= byte;
            for (unsigned bit = 0; bit < 8; ++bit)
                crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1U)));
        }
        return ~crc;
    }

    bytes_t make_zip(const json& recipe)
    {
        const auto format = recipe.at("format").get<std::string>();
        const auto zip64 = format == "zip64";
        std::string member_name = "fixture.bin";
        bytes_t member;
        if (format == "apk" || format == "aab") {
            member_name = "classes.dex";
            member = make_dex(recipe);
        } else if (format == "jar") {
            member_name = "aida/c03/corpus/Fixture.class";
            member = make_classfile(recipe);
        } else if (format == "ipa") {
            member_name = "Payload/Fixture.app/Fixture";
            json nested = recipe;
            nested["architecture"] = "aarch64";
            nested["mode"] = "64";
            nested["endian"] = "little";
            member = make_macho_thin(nested);
        } else if (format == "zip" || format == "zip64") {
            member_name = "fixture.exe";
            json nested = recipe;
            nested["architecture"] = "x64";
            nested["mode"] = "64";
            member = make_pe(nested);
        }
        const auto crc = crc32(member);
        bytes_t output;
        append_unsigned(output, 0x04034b50, 4, false);
        append_unsigned(output, zip64 ? 45 : 20, 2, false);
        append_unsigned(output, 0x0800, 2, false);
        append_unsigned(output, 0, 2, false);
        append_unsigned(output, 0, 2, false);
        append_unsigned(output, 0x0021, 2, false);
        append_unsigned(output, crc, 4, false);
        append_unsigned(output, zip64 ? 0xffffffffULL : member.size(), 4, false);
        append_unsigned(output, zip64 ? 0xffffffffULL : member.size(), 4, false);
        append_unsigned(output, member_name.size(), 2, false);
        append_unsigned(output, zip64 ? 20 : 0, 2, false);
        append_text(output, member_name);
        if (zip64) {
            append_unsigned(output, 0x0001, 2, false);
            append_unsigned(output, 16, 2, false);
            append_unsigned(output, member.size(), 8, false);
            append_unsigned(output, member.size(), 8, false);
        }
        output.insert(output.end(), member.begin(), member.end());
        const auto central_offset = output.size();
        append_unsigned(output, 0x02014b50, 4, false);
        append_unsigned(output, 45, 2, false);
        append_unsigned(output, zip64 ? 45 : 20, 2, false);
        append_unsigned(output, 0x0800, 2, false);
        append_unsigned(output, 0, 2, false);
        append_unsigned(output, 0, 2, false);
        append_unsigned(output, 0x0021, 2, false);
        append_unsigned(output, crc, 4, false);
        append_unsigned(output, zip64 ? 0xffffffffULL : member.size(), 4, false);
        append_unsigned(output, zip64 ? 0xffffffffULL : member.size(), 4, false);
        append_unsigned(output, member_name.size(), 2, false);
        append_unsigned(output, zip64 ? 28 : 0, 2, false);
        append_unsigned(output, 0, 2, false);
        append_unsigned(output, 0, 2, false);
        append_unsigned(output, 0, 2, false);
        append_unsigned(output, 0, 4, false);
        append_unsigned(output, zip64 ? 0xffffffffULL : 0, 4, false);
        append_text(output, member_name);
        if (zip64) {
            append_unsigned(output, 0x0001, 2, false);
            append_unsigned(output, 24, 2, false);
            append_unsigned(output, member.size(), 8, false);
            append_unsigned(output, member.size(), 8, false);
            append_unsigned(output, 0, 8, false);
        }
        const auto central_size = output.size() - central_offset;
        if (zip64) {
            const auto zip64_eocd_offset = output.size();
            append_unsigned(output, 0x06064b50, 4, false);
            append_unsigned(output, 44, 8, false);
            append_unsigned(output, 45, 2, false);
            append_unsigned(output, 45, 2, false);
            append_unsigned(output, 0, 4, false);
            append_unsigned(output, 0, 4, false);
            append_unsigned(output, 1, 8, false);
            append_unsigned(output, 1, 8, false);
            append_unsigned(output, central_size, 8, false);
            append_unsigned(output, central_offset, 8, false);
            append_unsigned(output, 0x07064b50, 4, false);
            append_unsigned(output, 0, 4, false);
            append_unsigned(output, zip64_eocd_offset, 8, false);
            append_unsigned(output, 1, 4, false);
        }
        append_unsigned(output, 0x06054b50, 4, false);
        append_unsigned(output, 0, 2, false);
        append_unsigned(output, 0, 2, false);
        append_unsigned(output, zip64 ? 0xffff : 1, 2, false);
        append_unsigned(output, zip64 ? 0xffff : 1, 2, false);
        append_unsigned(output, zip64 ? 0xffffffffULL : central_size, 4, false);
        append_unsigned(output, zip64 ? 0xffffffffULL : central_offset, 4, false);
        append_unsigned(output, 0, 2, false);
        return output;
    }

    bytes_t make_archive(const json& recipe)
    {
        bytes_t member;
        if (recipe.value("member_format", std::string("coff")) == "macho")
            member = make_macho_thin(recipe);
        else if (recipe.value("member_format", std::string("coff")) == "elf")
            member = make_elf(recipe);
        else
            member = make_coff(recipe);
        bytes_t output;
        append_text(output, "!<arch>\n");
        std::array<char, 60> header{};
        header.fill(' ');
        const std::string name = "fixture.o/";
        std::copy(name.begin(), name.end(), header.begin());
        const auto size = std::to_string(member.size());
        std::copy(size.begin(), size.end(), header.begin() + 48);
        header[58] = '`';
        header[59] = '\n';
        output.insert(output.end(), header.begin(), header.end());
        output.insert(output.end(), member.begin(), member.end());
        if ((output.size() & 1U) != 0U)
            output.push_back('\n');
        return output;
    }

    bytes_t build_artifact(const json& recipe)
    {
        const auto format = recipe.at("format").get<std::string>();
        if (format == "pe32" || format == "pe32plus" || format == "cli" || format == "readytorun")
            return make_pe(recipe);
        if (format == "coff")
            return make_coff(recipe);
        if (format == "elf32" || format == "elf64")
            return make_elf(recipe);
        if (format == "macho_thin")
            return make_macho_thin(recipe);
        if (format == "macho_fat")
            return make_macho_fat(recipe);
        if (format == "classfile")
            return make_classfile(recipe);
        if (format == "dex")
            return make_dex(recipe);
        if (format == "oat") {
            const auto dex = make_dex(recipe);
            bytes_t bytes(0x100U + dex.size(), 0);
            put_text(bytes, 0, "oat\n183\0");
            put_unsigned(bytes, 8, 0x1000, 4, false);
            std::copy(dex.begin(), dex.end(), bytes.begin() + 0x100U);
            return bytes;
        }
        if (format == "vdex") {
            const auto dex = make_dex(recipe);
            bytes_t bytes(0x100U + dex.size(), 0);
            put_text(bytes, 0, "vdex019\0");
            put_unsigned(bytes, 8, 1, 4, false);
            put_unsigned(bytes, 12, dex.size(), 4, false);
            std::copy(dex.begin(), dex.end(), bytes.begin() + 0x100U);
            return bytes;
        }
        if (format == "zip" || format == "zip64" || format == "apk" || format == "aab" ||
            format == "ipa" || format == "jar")
            return make_zip(recipe);
        if (format == "archive" || format == "static_library" || format == "import_library")
            return make_archive(recipe);
        if (format == "raw_code")
        {
            require(semantic_profile(recipe) == "native_zero",
                "raw-code fixture semantic profile must describe fragment");
            return native_fragment_code(recipe.at("architecture").get<std::string>(),
                recipe.at("mode").get<std::string>(), recipe.at("endian").get<std::string>());
        }
        throw materialization_error_t("unsupported fixture format: " + format);
    }

    std::string extension_for(std::string_view format)
    {
        if (format == "pe32" || format == "pe32plus" || format == "cli" || format == "readytorun") return ".exe";
        if (format == "coff") return ".obj";
        if (format == "elf32" || format == "elf64") return ".elf";
        if (format == "macho_thin" || format == "macho_fat") return ".macho";
        if (format == "classfile") return ".class";
        if (format == "dex") return ".dex";
        if (format == "oat") return ".oat";
        if (format == "vdex") return ".vdex";
        if (format == "archive" || format == "static_library" || format == "import_library") return ".a";
        if (format == "raw_code") return ".bin";
        return "." + std::string(format);
    }

    std::map<std::string, json, std::less<>> index_records(const json& array,
        std::string_view label)
    {
        require(array.is_array() && !array.empty(), std::string(label) + " must be a nonempty array");
        std::map<std::string, json, std::less<>> output;
        for (const auto& item : array) {
            require(item.is_object() && item.contains("id") && item.at("id").is_string() &&
                !item.at("id").get_ref<const std::string&>().empty(),
                std::string(label) + " contains an invalid identifier");
            const auto id = item.at("id").get<std::string>();
            require(output.emplace(id, item).second, std::string(label) + " contains a duplicate identifier");
        }
        return output;
    }

    void write_atomic(const std::filesystem::path& path, const bytes_t& bytes)
    {
        std::filesystem::create_directories(path.parent_path());
        const auto temporary = path.parent_path() / (path.filename().wstring() + L".aida.tmp");
        {
            std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
            require(stream.good(), "cannot create materialized fixture temporary file");
            stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
            require(stream.good(), "cannot write materialized fixture temporary file");
            stream.flush();
            require(stream.good(), "cannot flush materialized fixture temporary file");
        }
        std::error_code error;
        std::filesystem::remove(path, error);
        error.clear();
        std::filesystem::rename(temporary, path, error);
        require(!error, "cannot atomically publish materialized fixture");
    }

    std::string hash_json(const json& value)
    {
        const auto hash = canonical_json_sha256(value);
        require(hash.ok, hash.error);
        return hash.sha256;
    }

    bool equal_text(const json& left, const json& right, std::string_view field)
    {
        return left.contains(std::string(field)) && right.contains(std::string(field)) &&
            left.at(std::string(field)).is_string() && right.at(std::string(field)).is_string() &&
            left.at(std::string(field)) == right.at(std::string(field));
    }

    std::set<std::string, std::less<>> semantic_strings(
        const json& value, std::string_view label)
    {
        require(value.is_array(), std::string(label) + " must be an array");
        std::set<std::string, std::less<>> result;
        for (const auto& item : value) {
            require(item.is_string() && !item.get_ref<const std::string&>().empty() &&
                result.insert(item.get<std::string>()).second,
                std::string(label) + " contains an invalid or duplicate value");
        }
        return result;
    }

    std::string_view semantic_source(std::string_view profile)
    {
        if (profile == "native_conditional_dispatch" ||
            profile == "native_conditional_add" || profile == "native_sum" ||
            profile == "native_zero")
            return "source_corpus/native_fixture.c";
        if (profile == "managed_cli" || profile == "managed_cli_readytorun")
            return "source_corpus/managed_fixture.cs";
        if (profile == "jvm_fixture")
            return "source_corpus/Fixture.java";
        if (profile == "dalvik_fixture")
            return "source_corpus/Fixture.smali";
        throw materialization_error_t("semantic profile has no bound source corpus");
    }

    std::set<std::string, std::less<>> semantic_entities(
        const json& recipe, std::string_view profile)
    {
        if (profile == "native_conditional_dispatch")
            return {"fixture_add", "fixture_dispatch"};
        if (profile == "native_conditional_add")
            return {"fixture_add"};
        if (profile == "native_sum") {
            const auto& format = recipe.at("format").get_ref<const std::string&>();
            return format == "macho_thin" || format == "macho_fat" ||
                    format == "ipa" ?
                std::set<std::string, std::less<>>{"_fixture_sum"} :
                std::set<std::string, std::less<>>{"fixture_sum"};
        }
        if (profile == "native_zero")
            return {"fragment"};
        if (profile == "managed_cli" || profile == "managed_cli_readytorun")
            return {"AiDA.C03.Corpus.ManagedFixture.Add",
                "AiDA.C03.Corpus.ManagedFixture.GuardedDivide"};
        if (profile == "jvm_fixture")
            return {"aida.c03.corpus.Fixture.<init>",
                "aida.c03.corpus.Fixture.add",
                "aida.c03.corpus.Fixture.guardedDivide"};
        if (profile == "dalvik_fixture")
            return {"Laida/c03/corpus/Fixture;-><init>()V",
                "Laida/c03/corpus/Fixture;->add(II)I",
                "Laida/c03/corpus/Fixture;->guardedDivide(II)I"};
        throw materialization_error_t("semantic profile has no typed entity contract");
    }

    void validate_semantic_contract(const json& recipe, const json& truth,
        const json& ground_truth)
    {
        const auto profile = semantic_profile(recipe);
        const auto source = semantic_source(profile);
        require(truth.contains("source") && truth.at("source").is_string() &&
            std::string_view(truth.at("source").get_ref<const std::string&>()) == source &&
            ground_truth.contains("source_files") &&
            ground_truth.at("source_files").is_object() &&
            ground_truth.at("source_files").contains(std::string(source)) &&
            ground_truth.at("source_files").at(std::string(source)).is_string() &&
            is_canonical_sha256(ground_truth.at("source_files").at(
                std::string(source)).get_ref<const std::string&>()),
            "fixture recipe, truth, and source hash binding disagree");
        require(truth.contains("facts") && truth.at("facts").is_object(),
            "fixture ground truth omits semantic facts");
        const auto& facts = truth.at("facts");
        require(facts.contains("entities") &&
            semantic_strings(facts.at("entities"), "typed entities") ==
                semantic_entities(recipe, profile),
            "fixture typed entities disagree with its source semantic profile");
        require(facts.contains("control_structures"),
            "fixture ground truth omits control structures");
        const auto controls = semantic_strings(
            facts.at("control_structures"), "control structures");
        const auto require_controls = [&](std::initializer_list<std::string_view> values) {
            for (const auto value : values)
                require(controls.find(std::string(value)) != controls.end(),
                    "fixture ground truth omits a source control structure");
        };
        if (profile == "native_conditional_dispatch")
            require_controls({"if", "switch", "return"});
        else if (profile == "native_conditional_add")
            require_controls({"if", "return"});
        else if (profile == "managed_cli" ||
                 profile == "managed_cli_readytorun")
            require_controls({"conditional", "if", "throw", "return"});
        else if (profile == "jvm_fixture" || profile == "dalvik_fixture")
            require_controls({"try", "catch", "if", "throw", "return"});
        else
            require_controls({"return"});
        require(facts.contains("source_coordinates") &&
            !facts.at("source_coordinates").empty(),
            "fixture ground truth omits source coordinates");
        for (const auto& coordinate : facts.at("source_coordinates"))
            require(coordinate.is_string() &&
                coordinate.get_ref<const std::string&>().find(source) !=
                    std::string::npos,
                "fixture source coordinate is not bound to its source corpus");
    }

    bytes_t read_bounded(const std::filesystem::path& path, std::uint64_t maximum)
    {
        std::error_code error;
        const auto size = std::filesystem::file_size(path, error);
        require(!error && size != 0 && size <= maximum, "source fixture size is invalid for malformed materialization");
        bytes_t bytes(static_cast<std::size_t>(size));
        std::ifstream stream(path, std::ios::binary);
        require(static_cast<bool>(stream), "source fixture cannot be opened for malformed materialization");
        stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        require(stream.gcount() == static_cast<std::streamsize>(bytes.size()) && !stream.bad(),
            "source fixture read failed during malformed materialization");
        return bytes;
    }

    std::size_t find_signature(const bytes_t& bytes, std::string_view signature)
    {
        const auto found = std::search(bytes.begin(), bytes.end(), signature.begin(), signature.end());
        return found == bytes.end() ? bytes.size() : static_cast<std::size_t>(found - bytes.begin());
    }

    bytes_t mutate_fixture(bytes_t bytes, const json& record)
    {
        const auto mutation = record.at("mutation").get<std::string>();
        require(!bytes.empty(), "malformed mutation source is empty");
        if (mutation == "pe32_truncate_optional_header") {
            bytes.resize(std::min<std::size_t>(bytes.size(), 0x90U));
        } else if (mutation == "pe64_overlap_section_ranges") {
            require(bytes.size() >= 0x240U, "PE overlap source is too small");
            const auto pe = static_cast<std::size_t>(bytes[0x3c]) |
                (static_cast<std::size_t>(bytes[0x3d]) << 8U) |
                (static_cast<std::size_t>(bytes[0x3e]) << 16U) |
                (static_cast<std::size_t>(bytes[0x3f]) << 24U);
            const auto optional_size = static_cast<std::size_t>(bytes[pe + 20U]) |
                (static_cast<std::size_t>(bytes[pe + 21U]) << 8U);
            const auto section = pe + 24U + optional_size;
            ensure(bytes, section, 80U);
            put_unsigned(bytes, pe + 6U, 2U, 2U, false);
            std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(section), 40U,
                bytes.begin() + static_cast<std::ptrdiff_t>(section + 40U));
        } else if (mutation == "coff_symbol_count_overflow") {
            ensure(bytes, 8U, 12U);
            put_unsigned(bytes, 8U, 0xfffffff0U, 4U, false);
            put_unsigned(bytes, 12U, 0xffffffffU, 4U, false);
        } else if (mutation == "static_archive_recursive_member" || mutation == "aab_module_archive_cycle") {
            const auto original = bytes;
            for (unsigned depth = 0; depth < 12U; ++depth) {
                append_text(bytes, mutation == "static_archive_recursive_member" ? "!<arch>\n" : "PK\003\004");
                bytes.insert(bytes.end(), original.begin(), original.end());
            }
        } else if (mutation == "import_archive_member_length_out_of_range") {
            require(bytes.size() >= 68U, "archive length source is too small");
            const std::string length = "9999999999";
            std::copy(length.begin(), length.end(), bytes.begin() + 56);
        } else if (mutation == "cli_clear_metadata_signature" || mutation == "oat_unknown_version_signature") {
            const auto signature = mutation == "cli_clear_metadata_signature" ? std::string_view("BSJB") : std::string_view("oat\n183\0", 8U);
            const auto offset = find_signature(bytes, signature);
            require(offset != bytes.size(), "managed signature source is unavailable");
            std::fill_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset), signature.size(), 0);
        } else if (mutation == "readytorun_section_count_exceeds_directory") {
            require(bytes.size() >= 0x110U, "ReadyToRun source is too small");
            std::fill(bytes.begin() + 0x100, bytes.begin() + 0x110, 0xffU);
        } else if (mutation == "elf32_flip_encoding_without_swapping") {
            require(bytes.size() >= 6U, "ELF source is too small");
            bytes[5] = bytes[5] == 1U ? 2U : 1U;
        } else if (mutation == "elf64_program_header_offset_out_of_range") {
            require(bytes.size() >= 40U, "ELF64 source is too small");
            put_unsigned(bytes, 32U, (std::numeric_limits<std::uint64_t>::max)() - 15U, 8U, false);
        } else if (mutation == "macho_load_command_count_exceeds_size") {
            require(bytes.size() >= 24U, "Mach-O source is too small");
            put_unsigned(bytes, 16U, 0xffffffffU, 4U, false);
            put_unsigned(bytes, 20U, 8U, 4U, false);
        } else if (mutation == "macho_fat_slice_offset_out_of_range") {
            require(bytes.size() >= 20U, "fat Mach-O source is too small");
            put_unsigned(bytes, 16U, 0xfffffff0U, 4U, true);
        } else if (mutation == "zip_member_length_exceeds_container") {
            require(bytes.size() >= 26U, "ZIP source is too small");
            put_unsigned(bytes, 18U, 0xffffffffU, 4U, false);
            put_unsigned(bytes, 22U, 0xffffffffU, 4U, false);
        } else if (mutation == "zip64_inflate_ratio_exceeds_contract") {
            require(bytes.size() >= 26U, "ZIP64 source is too small");
            put_unsigned(bytes, 18U, 1U, 4U, false);
            put_unsigned(bytes, 22U, 0xffffffffU, 4U, false);
        } else if (mutation == "apk_duplicate_classes_dex_identity" || mutation == "jar_duplicate_class_identity") {
            const auto original = bytes;
            bytes.insert(bytes.end(), original.begin(), original.end());
        } else if (mutation == "dex_string_offset_plus_size_overflow") {
            require(bytes.size() >= 0x74U, "DEX source is too small");
            put_unsigned(bytes, 0x70U, 0xffffffffU, 4U, false);
        } else if (mutation == "vdex_embedded_dex_checksum_mismatch") {
            require(bytes.size() >= 16U, "VDEX source is too small");
            bytes[12U] ^= 0xffU;
        } else if (mutation == "ipa_member_path_traversal_utf8") {
            const auto offset = find_signature(bytes, "Payload/Fixture.app/Fixture");
            require(offset != bytes.size(), "IPA member path source is unavailable");
            const std::string replacement = "../evil/Fixture.app/Fixture";
            std::copy(replacement.begin(), replacement.end(), bytes.begin() + static_cast<std::ptrdiff_t>(offset));
            bytes[offset + replacement.size() - 1U] = 0xffU;
        } else if (mutation == "class_constant_pool_count_overflow") {
            require(bytes.size() >= 10U, "classfile source is too small");
            put_unsigned(bytes, 8U, 0xffffU, 2U, true);
        } else if (mutation == "raw_thumb_odd_range_identity_mismatch") {
            if ((bytes.size() & 1U) == 0U)
                bytes.pop_back();
            bytes.front() = 0xffU;
        } else {
            throw materialization_error_t("unsupported malformed fixture mutation: " + mutation);
        }
        require(!bytes.empty() && bytes.size() <= 64ULL * 1024ULL * 1024ULL,
            "malformed artifact exceeds the bounded output policy");
        return bytes;
    }
}

corpus_materialization_result_t materialize_c03_corpus(const json& manifest,
    const json& recipes, const json& ground_truth,
    const std::filesystem::path& output_root,
    const std::atomic_bool* cancellation)
{
    try {
        const auto manifest_validation = validate_corpus_manifest(manifest);
        require(manifest_validation.valid, manifest_validation.summary());
        require(recipes.is_object() && recipes.value("schema", std::string{}) == "aida.c03.corpus-generator-recipes" &&
            recipes.value("schema_version", 0) == 2 && recipes.contains("recipes"),
            "unsupported corpus recipe schema");
        require(ground_truth.is_object() && ground_truth.value("schema", std::string{}) == "aida.c03.corpus-ground-truth" &&
            ground_truth.value("schema_version", 0) == 1 && ground_truth.contains("fixtures"),
            "unsupported corpus ground-truth schema");
        require(recipes.value("target_execution_forbidden", false), "recipe contract must forbid target execution");
        require(ground_truth.value("target_execution_forbidden", false), "ground truth must forbid target execution");
        const auto recipe_index = index_records(recipes.at("recipes"), "recipe set");
        const auto truth_index = index_records(ground_truth.at("fixtures"), "ground-truth set");
        require(manifest.at("fixtures").size() == recipe_index.size() && recipe_index.size() == truth_index.size(),
            "manifest, recipe, and ground-truth fixture cardinality differ");
        require(recipe_index.size() <= 128, "fixture cardinality exceeds the bounded corpus limit");
        std::error_code error;
        std::filesystem::create_directories(output_root, error);
        require(!error && std::filesystem::is_directory(output_root), "materialization output root is unavailable");
        corpus_materialization_result_t result;
        result.fixtures.reserve(recipe_index.size());
        json receipt_fixtures = json::array();
        std::uint64_t total_bytes = 0;
        for (const auto& source_fixture : manifest.at("fixtures")) {
            if (cancellation && cancellation->load(std::memory_order_acquire))
                throw materialization_error_t("corpus materialization cancelled");
            json fixture = manifest.at("fixture_defaults");
            for (auto iterator = source_fixture.begin(); iterator != source_fixture.end(); ++iterator)
                fixture[iterator.key()] = iterator.value();
            if (!fixture.contains("container_chain"))
                fixture["container_chain"] = json::array({fixture.at("format")});
            const auto id = fixture.at("id").get<std::string>();
            const auto recipe_it = recipe_index.find(id);
            const auto truth_it = truth_index.find(id);
            require(recipe_it != recipe_index.end() && truth_it != truth_index.end(),
                "fixture lacks a recipe or ground-truth record: " + id);
            const auto& recipe = recipe_it->second;
            const auto& truth = truth_it->second;
            for (const auto field : {"format", "architecture", "mode", "endian"}) {
                require(equal_text(fixture, recipe, field) && equal_text(fixture, truth, field),
                    "fixture identity disagrees with recipe or ground truth: " + id);
            }
            validate_semantic_contract(recipe, truth, ground_truth);
            const auto bytes = build_artifact(recipe);
            require(!bytes.empty(), "materialized artifact is empty: " + id);
            const auto maximum = fixture.at("resource_limits").at("max_input_bytes").get<std::uint64_t>();
            require(bytes.size() <= maximum, "materialized artifact exceeds fixture input limit: " + id);
            require(total_bytes <= std::numeric_limits<std::uint64_t>::max() - bytes.size(),
                "materialized corpus byte count overflow");
            total_bytes += bytes.size();
            require(total_bytes <= 512ULL * 1024ULL * 1024ULL,
                "materialized corpus exceeds the 512 MiB package limit");
            const auto artifact_hash = sha256_evidence_bytes(bytes.data(), bytes.size());
            require(artifact_hash.ok, artifact_hash.error);
            const auto recipe_hash = hash_json(recipe);
            const auto truth_hash = hash_json(truth);
            const auto path = output_root / std::filesystem::u8path(id + extension_for(fixture.at("format").get<std::string>()));
            write_atomic(path, bytes);
            const auto disk_hash = sha256_evidence_file(path, maximum);
            require(disk_hash.ok && disk_hash.sha256 == artifact_hash.sha256,
                disk_hash.ok ? "published artifact hash mismatch" : disk_hash.error);
            materialized_fixture_t materialized{id, path, artifact_hash.sha256, recipe_hash, truth_hash,
                static_cast<std::uint64_t>(bytes.size()), fixture.at("format").get<std::string>(),
                fixture.at("architecture").get<std::string>(), fixture.at("mode").get<std::string>(),
                fixture.at("endian").get<std::string>()};
            receipt_fixtures.push_back({{"id", id}, {"relative_path", path.filename().u8string()},
                {"artifact_sha256", materialized.artifact_sha256}, {"recipe_sha256", recipe_hash},
                {"ground_truth_sha256", truth_hash}, {"size_bytes", materialized.size_bytes},
                {"format", materialized.format}, {"architecture", materialized.architecture},
                {"mode", materialized.mode}, {"endian", materialized.endian},
                {"target_execution_forbidden", true}});
            result.fixtures.push_back(std::move(materialized));
        }
        result.receipt = {{"schema", "aida.c03.corpus-materialization-receipt"}, {"schema_version", 1},
            {"manifest_sha256", hash_json(manifest)}, {"recipes_sha256", hash_json(recipes)},
            {"ground_truth_sha256", hash_json(ground_truth)}, {"target_execution_forbidden", true},
            {"total_bytes", total_bytes}, {"fixtures", std::move(receipt_fixtures)},
            {"receipt_sha256", ""}};
        const auto receipt_hash = canonical_json_sha256(result.receipt, "receipt_sha256");
        require(receipt_hash.ok, receipt_hash.error);
        result.receipt["receipt_sha256"] = receipt_hash.sha256;
        result.ok = true;
        return result;
    } catch (const std::exception& error) {
        return {false, error.what(), {}, {}};
    }
}

contract_validation_result_t validate_materialization_receipt(const json& receipt,
    const json& manifest, const json& recipes, const json& ground_truth,
    const std::filesystem::path& output_root)
{
    contract_validation_result_t result;
    if (!receipt.is_object()) {
        result.reject("", "object_required", "materialization receipt must be an object");
        return result;
    }
    static const std::set<std::string, std::less<>> allowed{"schema", "schema_version", "manifest_sha256",
        "recipes_sha256", "ground_truth_sha256", "target_execution_forbidden", "total_bytes", "fixtures", "receipt_sha256"};
    for (auto iterator = receipt.begin(); iterator != receipt.end(); ++iterator) {
        if (allowed.find(iterator.key()) == allowed.end())
            result.reject("/" + iterator.key(), "unknown_field", "unknown materialization receipt field");
    }
    for (const auto field : allowed) {
        if (!receipt.contains(field))
            result.reject("/" + field, "required", "materialization receipt field is required");
    }
    if (!result.valid)
        return result;
    if (receipt.at("schema") != "aida.c03.corpus-materialization-receipt" || receipt.at("schema_version") != 1)
        result.reject("/schema", "schema_id", "unsupported materialization receipt schema");
    if (!receipt.at("target_execution_forbidden").is_boolean() || !receipt.at("target_execution_forbidden").get<bool>())
        result.reject("/target_execution_forbidden", "target_execution", "target execution must remain forbidden");
    const auto expected_manifest = canonical_json_sha256(manifest);
    const auto expected_recipes = canonical_json_sha256(recipes);
    const auto expected_truth = canonical_json_sha256(ground_truth);
    for (const auto binding : std::array<std::pair<std::string_view, const evidence_hash_result_t*>, 3>{
             std::pair<std::string_view, const evidence_hash_result_t*>{"manifest_sha256", &expected_manifest},
             {"recipes_sha256", &expected_recipes}, {"ground_truth_sha256", &expected_truth}}) {
        if (!binding.second->ok || !receipt.at(std::string(binding.first)).is_string() ||
            receipt.at(std::string(binding.first)) != binding.second->sha256)
            result.reject("/" + std::string(binding.first), "hash_binding", "materialization source hash mismatch");
    }
    std::string hash_error;
    if (!verify_canonical_receipt_hash(receipt, "receipt_sha256", hash_error))
        result.reject("/receipt_sha256", "receipt_hash", hash_error);
    if (!receipt.at("fixtures").is_array() || receipt.at("fixtures").empty()) {
        result.reject("/fixtures", "min_items", "materialized fixture evidence is required");
        return result;
    }
    std::set<std::string, std::less<>> ids;
    std::uint64_t total = 0;
    for (std::size_t index = 0; index < receipt.at("fixtures").size(); ++index) {
        const auto& fixture = receipt.at("fixtures")[index];
        const auto path = "/fixtures/" + std::to_string(index);
        if (!fixture.is_object() || !fixture.contains("id") || !fixture.at("id").is_string() ||
            !ids.insert(fixture.at("id").get<std::string>()).second) {
            result.reject(path + "/id", "duplicate_or_invalid", "fixture identifier is invalid or duplicated");
            continue;
        }
        if (!fixture.contains("relative_path") || !fixture.at("relative_path").is_string()) {
            result.reject(path + "/relative_path", "required", "materialized relative path is required");
            continue;
        }
        const auto relative = std::filesystem::u8path(fixture.at("relative_path").get<std::string>());
        if (relative.is_absolute() || relative.has_parent_path()) {
            result.reject(path + "/relative_path", "path_scope", "materialized path must be one output-root filename");
            continue;
        }
        const auto disk_hash = sha256_evidence_file(output_root / relative, 64ULL * 1024ULL * 1024ULL);
        if (!disk_hash.ok || !fixture.contains("artifact_sha256") || !fixture.at("artifact_sha256").is_string() ||
            disk_hash.sha256 != fixture.at("artifact_sha256").get<std::string>())
            result.reject(path + "/artifact_sha256", "artifact_hash", disk_hash.ok ? "artifact hash mismatch" : disk_hash.error);
        if (!fixture.contains("size_bytes") || !fixture.at("size_bytes").is_number_unsigned())
            result.reject(path + "/size_bytes", "nonnegative_integer_required", "artifact byte size is required");
        else if (total > std::numeric_limits<std::uint64_t>::max() - fixture.at("size_bytes").get<std::uint64_t>())
            result.reject(path + "/size_bytes", "aggregate_overflow", "materialized byte total overflow");
        else
            total += fixture.at("size_bytes").get<std::uint64_t>();
        if (!fixture.value("target_execution_forbidden", false))
            result.reject(path + "/target_execution_forbidden", "target_execution", "fixture execution is forbidden");
    }
    if (!receipt.at("total_bytes").is_number_unsigned() || receipt.at("total_bytes").get<std::uint64_t>() != total)
        result.reject("/total_bytes", "aggregate_mismatch", "materialized byte total disagrees with fixture rows");
    if (ids.size() != manifest.at("fixtures").size())
        result.reject("/fixtures", "coverage_missing", "materialization receipt does not cover every corpus fixture");
    return result;
}

corpus_materialization_result_t materialize_c03_malformed_corpus(const json& malformed_cases,
    const std::vector<materialized_fixture_t>& source_fixtures,
    const std::filesystem::path& output_root, const std::atomic_bool* cancellation)
{
    try {
        require(malformed_cases.is_object() && malformed_cases.value("schema", std::string{}) == "aida.c03.malformed-cases" &&
            malformed_cases.value("schema_version", 0) == 1 && malformed_cases.value("target_execution_forbidden", false) &&
            malformed_cases.contains("cases") && malformed_cases.at("cases").is_array(),
            "unsupported malformed-case manifest");
        std::map<std::string, materialized_fixture_t, std::less<>> sources;
        for (const auto& source : source_fixtures)
            require(sources.emplace(source.id, source).second, "duplicate source fixture for malformed materialization");
        std::error_code filesystem_error;
        std::filesystem::create_directories(output_root, filesystem_error);
        require(!filesystem_error && std::filesystem::is_directory(output_root),
            "malformed materialization output root is unavailable");
        corpus_materialization_result_t output;
        json rows = json::array();
        std::uint64_t total = 0;
        std::set<std::string, std::less<>> identifiers;
        for (const auto& record : malformed_cases.at("cases")) {
            if (cancellation && cancellation->load(std::memory_order_acquire))
                throw materialization_error_t("malformed corpus materialization cancelled");
            require(record.is_object() && record.contains("id") && record.at("id").is_string() &&
                record.contains("source_fixture_id") && record.at("source_fixture_id").is_string() &&
                record.contains("mutation") && record.at("mutation").is_string() &&
                record.value("target_execution_forbidden", false),
                "malformed-case identity or non-execution contract is invalid");
            const auto id = record.at("id").get<std::string>();
            const auto source_id = record.at("source_fixture_id").get<std::string>();
            require(!id.empty() && std::all_of(id.begin(), id.end(), [](unsigned char character) {
                return std::isalnum(character) != 0 || character == '-' || character == '_';
            }) && identifiers.insert(id).second, "malformed-case identifier is unsafe or duplicated");
            require(record.contains("expected_error_codes") && record.at("expected_error_codes").is_array() &&
                !record.at("expected_error_codes").empty(), "malformed case requires expected parser diagnostics");
            const auto source = sources.find(source_id);
            require(source != sources.end(), "malformed case references an absent source fixture: " + source_id);
            auto bytes = mutate_fixture(read_bounded(source->second.path, 64ULL * 1024ULL * 1024ULL), record);
            const auto hash = sha256_evidence_bytes(bytes.data(), bytes.size());
            require(hash.ok, hash.error);
            const auto path = output_root / std::filesystem::u8path(id + ".malformed");
            write_atomic(path, bytes);
            const auto disk_hash = sha256_evidence_file(path, 64ULL * 1024ULL * 1024ULL);
            require(disk_hash.ok && disk_hash.sha256 == hash.sha256,
                disk_hash.ok ? "malformed artifact hash mismatch" : disk_hash.error);
            const auto case_hash = hash_json(record);
            output.fixtures.push_back({id, path, hash.sha256, case_hash, source->second.artifact_sha256,
                static_cast<std::uint64_t>(bytes.size()), source->second.format, source->second.architecture,
                source->second.mode, source->second.endian});
            rows.push_back({{"id", id}, {"source_fixture_id", source_id}, {"relative_path", path.filename().u8string()},
                {"artifact_sha256", hash.sha256}, {"case_sha256", case_hash},
                {"source_artifact_sha256", source->second.artifact_sha256}, {"size_bytes", bytes.size()},
                {"expected_error_codes", record.at("expected_error_codes")}, {"target_execution_forbidden", true}});
            require(total <= (std::numeric_limits<std::uint64_t>::max)() - bytes.size(),
                "malformed corpus byte total overflow");
            total += bytes.size();
        }
        output.receipt = {{"schema", "aida.c03.malformed-materialization-receipt"}, {"schema_version", 1},
            {"case_manifest_sha256", hash_json(malformed_cases)}, {"target_execution_forbidden", true},
            {"total_bytes", total}, {"fixtures", std::move(rows)}, {"receipt_sha256", ""}};
        const auto receipt_hash = canonical_json_sha256(output.receipt, "receipt_sha256");
        require(receipt_hash.ok, receipt_hash.error);
        output.receipt["receipt_sha256"] = receipt_hash.sha256;
        output.ok = true;
        return output;
    } catch (const std::exception& error) {
        return {false, error.what(), {}, {}};
    }
}

contract_validation_result_t validate_malformed_materialization_receipt(const json& receipt,
    const json& malformed_cases, const std::filesystem::path& output_root)
{
    contract_validation_result_t result;
    if (!receipt.is_object() || receipt.value("schema", std::string{}) != "aida.c03.malformed-materialization-receipt" ||
        receipt.value("schema_version", 0) != 1 || !receipt.value("target_execution_forbidden", false) ||
        !receipt.contains("fixtures") || !receipt.at("fixtures").is_array()) {
        result.reject("", "receipt_schema", "malformed materialization receipt schema is invalid");
        return result;
    }
    const std::set<std::string, std::less<>> receipt_fields{"schema", "schema_version", "case_manifest_sha256",
        "target_execution_forbidden", "total_bytes", "fixtures", "receipt_sha256"};
    for (auto iterator = receipt.begin(); iterator != receipt.end(); ++iterator) {
        if (receipt_fields.find(iterator.key()) == receipt_fields.end())
            result.reject("/" + iterator.key(), "additional_property", "malformed receipt field is not allowed");
    }
    const auto source_hash = canonical_json_sha256(malformed_cases);
    if (!source_hash.ok || receipt.value("case_manifest_sha256", std::string{}) != source_hash.sha256)
        result.reject("/case_manifest_sha256", "hash_binding", "malformed-case manifest hash mismatch");
    std::string receipt_error;
    if (!verify_canonical_receipt_hash(receipt, "receipt_sha256", receipt_error))
        result.reject("/receipt_sha256", "receipt_hash", receipt_error);
    std::set<std::string, std::less<>> identifiers;
    std::map<std::string, json, std::less<>> expected_cases;
    if (!malformed_cases.is_object() || !malformed_cases.contains("cases") ||
        !malformed_cases.at("cases").is_array()) {
        result.reject("/case_manifest_sha256", "case_manifest", "malformed-case manifest is invalid");
        return result;
    }
    for (const auto& expected : malformed_cases.at("cases")) {
        if (!expected.is_object() || !expected.contains("id") || !expected.at("id").is_string() ||
            !expected_cases.emplace(expected.at("id").get<std::string>(), expected).second)
            result.reject("/case_manifest_sha256", "case_manifest", "malformed-case identity is invalid or duplicated");
    }
    std::uint64_t total = 0;
    for (std::size_t index = 0; index < receipt.at("fixtures").size(); ++index) {
        const auto& fixture = receipt.at("fixtures")[index];
        const auto base = "/fixtures/" + std::to_string(index);
        if (fixture.is_object()) {
            const std::set<std::string, std::less<>> fields{"id", "source_fixture_id", "relative_path",
                "artifact_sha256", "case_sha256", "source_artifact_sha256", "size_bytes",
                "expected_error_codes", "target_execution_forbidden"};
            for (auto iterator = fixture.begin(); iterator != fixture.end(); ++iterator) {
                if (fields.find(iterator.key()) == fields.end())
                    result.reject(base + "/" + iterator.key(), "additional_property", "malformed fixture field is not allowed");
            }
        }
        if (!fixture.is_object() || !fixture.contains("id") || !fixture.at("id").is_string() ||
            !identifiers.insert(fixture.at("id").get<std::string>()).second ||
            !fixture.value("target_execution_forbidden", false)) {
            result.reject(base, "fixture_identity", "malformed fixture identity or non-execution contract is invalid");
            continue;
        }
        const auto id = fixture.at("id").get<std::string>();
        const auto expected = expected_cases.find(id);
        if (expected == expected_cases.end()) {
            result.reject(base + "/id", "case_binding", "malformed fixture is absent from the case manifest");
            continue;
        }
        const auto expected_case_hash = canonical_json_sha256(expected->second);
        if (!expected_case_hash.ok || fixture.value("case_sha256", std::string{}) != expected_case_hash.sha256)
            result.reject(base + "/case_sha256", "case_binding", "malformed fixture case hash is invalid");
        if (!equal_text(fixture, expected->second, "source_fixture_id"))
            result.reject(base + "/source_fixture_id", "case_binding", "malformed fixture source identity differs from its case");
        if (!fixture.contains("expected_error_codes") ||
            fixture.at("expected_error_codes") != expected->second.value("expected_error_codes", json::array()))
            result.reject(base + "/expected_error_codes", "case_binding", "malformed fixture diagnostics differ from its case");
        const auto relative = std::filesystem::u8path(fixture.value("relative_path", std::string{}));
        if (relative.empty() || relative.is_absolute() || relative.has_parent_path() ||
            relative.u8string() != id + ".malformed") {
            result.reject(base + "/relative_path", "path_scope", "malformed fixture path is invalid");
            continue;
        }
        const auto hash = sha256_evidence_file(output_root / relative, 64ULL * 1024ULL * 1024ULL);
        if (!hash.ok || fixture.value("artifact_sha256", std::string{}) != hash.sha256)
            result.reject(base + "/artifact_sha256", "artifact_hash", hash.ok ? "malformed artifact hash mismatch" : hash.error);
        std::error_code size_error;
        const auto observed_size = std::filesystem::file_size(output_root / relative, size_error);
        if (!fixture.contains("size_bytes") || !fixture.at("size_bytes").is_number_unsigned() || size_error ||
            fixture.at("size_bytes").get<std::uint64_t>() != observed_size ||
            total > (std::numeric_limits<std::uint64_t>::max)() - fixture.value("size_bytes", 0ULL))
            result.reject(base + "/size_bytes", "size", "malformed artifact size is invalid");
        else
            total += fixture.at("size_bytes").get<std::uint64_t>();
    }
    if (identifiers.size() != expected_cases.size())
        result.reject("/fixtures", "coverage", "malformed materialization does not cover every case");
    if (!receipt.contains("total_bytes") || !receipt.at("total_bytes").is_number_unsigned() ||
        receipt.at("total_bytes").get<std::uint64_t>() != total)
        result.reject("/total_bytes", "aggregate", "malformed artifact byte total is invalid");
    return result;
}
}
