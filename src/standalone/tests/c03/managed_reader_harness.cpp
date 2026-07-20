#include "managed_reader_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/readers/managed/managed_reader_contracts.hpp"
#include "../../src/core/analysis/readers/managed/cli_metadata_reader.hpp"
#include "../../src/core/analysis/readers/managed/classfile_reader.hpp"
#include "../../src/core/analysis/readers/managed/dex_reader.hpp"
#include "../../src/core/analysis/decompiler/managed_entity_binding.hpp"
#include "../../src/core/analysis/decompiler/providers/dalvik_ssa.hpp"
#include "../../src/core/analysis/decompiler/providers/jvm_ssa.hpp"
#include "../../src/core/analysis/workspace/analysis_workspace.hpp"
#include "../../src/core/analysis/workspace/byte_provider.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace aida::analysis::c03_test {
namespace {

namespace mr = ::aida::analysis::readers::managed;

using ::aida::analysis::byte_provider_t;
using ::aida::analysis::byte_view_t;
using ::aida::analysis::cancellation_source_t;
using ::aida::analysis::cancellation_token_t;
using ::aida::analysis::mapped_file_provider_t;
using ::aida::analysis::workspace_error_code_t;
using ::aida::analysis::workspace_result_t;

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
        throw std::runtime_error(std::string(message) + ": " + result.error().stable_code());
    return result.take_value();
}

void write_be16(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value) {
    require(offset + 2 <= bytes.size(), "write_be16 out of bounds");
    bytes[offset] = static_cast<std::uint8_t>(value >> 8);
    bytes[offset + 1] = static_cast<std::uint8_t>(value & 0xFF);
}

void write_be32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
    require(offset + 4 <= bytes.size(), "write_be32 out of bounds");
    bytes[offset] = static_cast<std::uint8_t>(value >> 24);
    bytes[offset + 1] = static_cast<std::uint8_t>(value >> 16);
    bytes[offset + 2] = static_cast<std::uint8_t>(value >> 8);
    bytes[offset + 3] = static_cast<std::uint8_t>(value & 0xFF);
}

void write_le16(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value) {
    require(offset + 2 <= bytes.size(), "write_le16 out of bounds");
    bytes[offset] = static_cast<std::uint8_t>(value & 0xFF);
    bytes[offset + 1] = static_cast<std::uint8_t>(value >> 8);
}

void write_le32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
    require(offset + 4 <= bytes.size(), "write_le32 out of bounds");
    bytes[offset] = static_cast<std::uint8_t>(value & 0xFF);
    bytes[offset + 1] = static_cast<std::uint8_t>(value >> 8);
    bytes[offset + 2] = static_cast<std::uint8_t>(value >> 16);
    bytes[offset + 3] = static_cast<std::uint8_t>(value >> 24);
}

class temp_fixture_t {
public:
    explicit temp_fixture_t(const std::vector<std::uint8_t>& bytes, const char* suffix = ".bin") {
        path_ = std::filesystem::temp_directory_path() /
                ("aida_managed_reader_test_" + std::to_string(counter_++) + suffix);
        std::ofstream output(path_, std::ios::binary | std::ios::trunc);
        require(output.is_open(), "failed to create temp fixture file");
        output.write(reinterpret_cast<const char*>(bytes.data()),
                     static_cast<std::streamsize>(bytes.size()));
        output.close();
    }

    ~temp_fixture_t() {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }

    temp_fixture_t(const temp_fixture_t&) = delete;
    temp_fixture_t& operator=(const temp_fixture_t&) = delete;

    const std::filesystem::path& path() const noexcept { return path_; }

    std::shared_ptr<mapped_file_provider_t> open_provider() {
        auto result = mapped_file_provider_t::open(path_.u8string());
        if (!result)
            throw std::runtime_error("failed to open mapped file provider for fixture");
        return result.take_value();
    }

private:
    std::filesystem::path path_;
    static std::uint64_t counter_;
};

std::uint64_t temp_fixture_t::counter_ = 0;

std::shared_ptr<const workspace_identity_t> make_fixture_identity(
    const std::shared_ptr<mapped_file_provider_t>& provider,
    format_id_t format,
    architecture_id_t architecture,
    architecture_mode_t mode,
    abi_id_t abi,
    endian_t endian,
    const std::string& profile) {
    auto content_hash = provider->compute_content_sha256();
    auto profile_hash = sha256_text(profile);
    require(content_hash.has_value() && profile_hash.has_value(),
            "fixture hashes were not created");
    workspace_identity_input_t input;
    input.bin_name = std::filesystem::path(
        provider->identity().normalized_source).filename().u8string();
    input.source_path = provider->identity().normalized_source;
    input.content_hash = content_hash.take_value();
    input.load_profile_hash = profile_hash.take_value();
    input.target_kind = target_kind_t::static_file;
    input.format = format;
    input.architecture = architecture;
    input.architecture_mode = mode;
    input.abi = abi;
    input.endian = endian;
    auto identity = make_workspace_identity(std::move(input));
    if (!identity)
        throw std::runtime_error(
            std::string("fixture identity creation failed: ") +
            identity.error().stable_code());
    return identity.take_value();
}

std::shared_ptr<const analysis_publication_t> make_fixture_publication(
    const std::shared_ptr<const workspace_identity_t>& identity,
    const std::shared_ptr<mapped_file_provider_t>& provider,
    const std::shared_ptr<const managed_artifact_publication_t>& managed) {
    auto snapshot = std::make_shared<analysis_snapshot_t>();
    snapshot->binary_id = identity->binary_id();
    snapshot->load_profile_hash = identity->load_profile_hash();
    snapshot->generation = managed->generation;
    snapshot->analysis_revision = managed->analysis_revision;
    snapshot->overlay_revision = managed->overlay_revision;
    auto publication = std::make_shared<analysis_publication_t>(
        std::static_pointer_cast<const analysis_snapshot_t>(snapshot),
        std::static_pointer_cast<const byte_provider_t>(provider), nullptr,
        workspace_readiness_t::provider_ready, managed);
    require(publication->coherent_with(*identity),
            "fixture analysis publication is incoherent");
    return publication;
}

std::shared_ptr<analysis_workspace_t> open_fixture_workspace(
    const std::shared_ptr<const workspace_identity_t>& identity,
    const std::shared_ptr<mapped_file_provider_t>& provider) {
    auto image = std::make_shared<workspace_image_t>();
    image->format = identity->format();
    image->architecture = identity->architecture();
    image->architecture_mode = identity->architecture_mode();
    image->abi = identity->abi();
    image->endian = identity->endian();
    image->address_width_bits = 32;
    image->image_base = identity->image_base();
    image->image_size = provider->size();
    image->header_size = (std::min<std::uint64_t>)(provider->size(), 112);
    image->format_name = "c03-managed-fixture";
    image->provider_size = provider->size();
    auto workspace = analysis_workspace_t::create_normalized(
        identity, std::static_pointer_cast<const byte_provider_t>(provider),
        std::static_pointer_cast<const workspace_image_t>(image));
    if (!workspace)
        throw std::runtime_error(
            std::string("fixture workspace creation failed: ") +
            workspace.error().stable_code());
    return workspace.take_value();
}

decompiler_provider_identity_t make_fixture_provider(
    decompiler_provider_id_t provider, const std::string& name) {
    decompiler_provider_identity_t identity;
    identity.provider = provider;
    identity.provider_name = name;
    identity.provider_version = "c03-fixture-v1";
    identity.provider_binary_hash = require_value(
        sha256_text(name + "|binary"), "fixture provider hash failed");
    identity.worker_build_id = name + "-worker";
    identity.worker_build_hash = require_value(
        sha256_text(name + "|worker"), "fixture worker hash failed");
    return identity;
}

std::vector<std::uint8_t> make_minimal_classfile() {
    std::vector<std::uint8_t> bytes(256, 0);
    std::size_t offset = 0;

    write_be32(bytes, offset, 0xCAFEBABE); offset += 4;
    write_be16(bytes, offset, 0); offset += 2;
    write_be16(bytes, offset, 52); offset += 2;
    write_be16(bytes, offset, 15); offset += 2;

    bytes[offset++] = 1;
    write_be16(bytes, offset, 5); offset += 2;
    std::memcpy(&bytes[offset], "Hello", 5); offset += 5;

    bytes[offset++] = 7;
    write_be16(bytes, offset, 1); offset += 2;

    bytes[offset++] = 1;
    write_be16(bytes, offset, 16); offset += 2;
    std::memcpy(&bytes[offset], "java/lang/Object", 16); offset += 16;

    bytes[offset++] = 7;
    write_be16(bytes, offset, 3); offset += 2;

    bytes[offset++] = 1;
    write_be16(bytes, offset, 6); offset += 2;
    std::memcpy(&bytes[offset], "<init>", 6); offset += 6;

    bytes[offset++] = 1;
    write_be16(bytes, offset, 3); offset += 2;
    std::memcpy(&bytes[offset], "()V", 3); offset += 3;

    bytes[offset++] = 12;
    write_be16(bytes, offset, 5); offset += 2;
    write_be16(bytes, offset, 6); offset += 2;

    bytes[offset++] = 10;
    write_be16(bytes, offset, 4); offset += 2;
    write_be16(bytes, offset, 7); offset += 2;

    bytes[offset++] = 1;
    write_be16(bytes, offset, 5); offset += 2;
    std::memcpy(&bytes[offset], "value", 5); offset += 5;

    bytes[offset++] = 1;
    write_be16(bytes, offset, 1); offset += 2;
    std::memcpy(&bytes[offset], "I", 1); offset += 1;

    bytes[offset++] = 12;
    write_be16(bytes, offset, 9); offset += 2;
    write_be16(bytes, offset, 10); offset += 2;

    bytes[offset++] = 9;
    write_be16(bytes, offset, 2); offset += 2;
    write_be16(bytes, offset, 11); offset += 2;

    bytes[offset++] = 1;
    write_be16(bytes, offset, 4); offset += 2;
    std::memcpy(&bytes[offset], "test", 4); offset += 4;

    bytes[offset++] = 1;
    write_be16(bytes, offset, 4); offset += 2;
    std::memcpy(&bytes[offset], "Code", 4); offset += 4;

    write_be16(bytes, offset, 0x0021); offset += 2;
    write_be16(bytes, offset, 2); offset += 2;
    write_be16(bytes, offset, 4); offset += 2;
    write_be16(bytes, offset, 0); offset += 2;
    write_be16(bytes, offset, 1); offset += 2;

    write_be16(bytes, offset, 0x0019); offset += 2;
    write_be16(bytes, offset, 9); offset += 2;
    write_be16(bytes, offset, 10); offset += 2;
    write_be16(bytes, offset, 0); offset += 2;

    write_be16(bytes, offset, 2); offset += 2;

    write_be16(bytes, offset, 0x0001); offset += 2;
    write_be16(bytes, offset, 5); offset += 2;
    write_be16(bytes, offset, 6); offset += 2;
    write_be16(bytes, offset, 1); offset += 2;

    write_be16(bytes, offset, 14); offset += 2;
    write_be32(bytes, offset, 25); offset += 4;
    write_be16(bytes, offset, 1); offset += 2;
    write_be16(bytes, offset, 0); offset += 2;
    write_be32(bytes, offset, 5); offset += 4;
    bytes[offset++] = 0x2A;
    bytes[offset++] = 0xB7;
    bytes[offset++] = 0x00;
    bytes[offset++] = 0x08;
    bytes[offset++] = 0xB1;
    write_be16(bytes, offset, 1); offset += 2;
    write_be16(bytes, offset, 0); offset += 2;
    write_be16(bytes, offset, 5); offset += 2;
    write_be16(bytes, offset, 0); offset += 2;
    write_be16(bytes, offset, 0); offset += 2;
    write_be16(bytes, offset, 0); offset += 2;

    write_be16(bytes, offset, 0x0001); offset += 2;
    write_be16(bytes, offset, 13); offset += 2;
    write_be16(bytes, offset, 6); offset += 2;
    write_be16(bytes, offset, 1); offset += 2;

    write_be16(bytes, offset, 14); offset += 2;
    write_be32(bytes, offset, 13); offset += 4;
    write_be16(bytes, offset, 1); offset += 2;
    write_be16(bytes, offset, 0); offset += 2;
    write_be32(bytes, offset, 1); offset += 4;
    bytes[offset++] = 0xB1;
    write_be16(bytes, offset, 0); offset += 2;
    write_be16(bytes, offset, 0); offset += 2;

    write_be16(bytes, offset, 0); offset += 2;

    bytes.resize(offset);
    return bytes;
}

std::vector<std::uint8_t> make_classfile_with_duplicate_methods() {
    std::vector<std::uint8_t> bytes(256, 0);
    std::size_t offset = 0;

    write_be32(bytes, offset, 0xCAFEBABE); offset += 4;
    write_be16(bytes, offset, 0); offset += 2;
    write_be16(bytes, offset, 52); offset += 2;
    write_be16(bytes, offset, 15); offset += 2;

    bytes[offset++] = 1;
    write_be16(bytes, offset, 5); offset += 2;
    std::memcpy(&bytes[offset], "Hello", 5); offset += 5;

    bytes[offset++] = 7;
    write_be16(bytes, offset, 1); offset += 2;

    bytes[offset++] = 1;
    write_be16(bytes, offset, 16); offset += 2;
    std::memcpy(&bytes[offset], "java/lang/Object", 16); offset += 16;

    bytes[offset++] = 7;
    write_be16(bytes, offset, 3); offset += 2;

    bytes[offset++] = 1;
    write_be16(bytes, offset, 6); offset += 2;
    std::memcpy(&bytes[offset], "<init>", 6); offset += 6;

    bytes[offset++] = 1;
    write_be16(bytes, offset, 3); offset += 2;
    std::memcpy(&bytes[offset], "()V", 3); offset += 3;

    bytes[offset++] = 12;
    write_be16(bytes, offset, 5); offset += 2;
    write_be16(bytes, offset, 6); offset += 2;

    bytes[offset++] = 10;
    write_be16(bytes, offset, 4); offset += 2;
    write_be16(bytes, offset, 7); offset += 2;

    bytes[offset++] = 1;
    write_be16(bytes, offset, 5); offset += 2;
    std::memcpy(&bytes[offset], "value", 5); offset += 5;

    bytes[offset++] = 1;
    write_be16(bytes, offset, 1); offset += 2;
    std::memcpy(&bytes[offset], "I", 1); offset += 1;

    bytes[offset++] = 12;
    write_be16(bytes, offset, 9); offset += 2;
    write_be16(bytes, offset, 10); offset += 2;

    bytes[offset++] = 9;
    write_be16(bytes, offset, 2); offset += 2;
    write_be16(bytes, offset, 11); offset += 2;

    bytes[offset++] = 1;
    write_be16(bytes, offset, 4); offset += 2;
    std::memcpy(&bytes[offset], "test", 4); offset += 4;

    bytes[offset++] = 1;
    write_be16(bytes, offset, 4); offset += 2;
    std::memcpy(&bytes[offset], "Code", 4); offset += 4;

    write_be16(bytes, offset, 0x0021); offset += 2;
    write_be16(bytes, offset, 2); offset += 2;
    write_be16(bytes, offset, 4); offset += 2;
    write_be16(bytes, offset, 0); offset += 2;
    write_be16(bytes, offset, 0); offset += 2;

    write_be16(bytes, offset, 2); offset += 2;

    write_be16(bytes, offset, 0x0001); offset += 2;
    write_be16(bytes, offset, 5); offset += 2;
    write_be16(bytes, offset, 6); offset += 2;
    write_be16(bytes, offset, 1); offset += 2;

    write_be16(bytes, offset, 14); offset += 2;
    write_be32(bytes, offset, 13); offset += 4;
    write_be16(bytes, offset, 1); offset += 2;
    write_be16(bytes, offset, 0); offset += 2;
    write_be32(bytes, offset, 1); offset += 4;
    bytes[offset++] = 0xB1;
    write_be16(bytes, offset, 0); offset += 2;
    write_be16(bytes, offset, 0); offset += 2;

    write_be16(bytes, offset, 0x0001); offset += 2;
    write_be16(bytes, offset, 5); offset += 2;
    write_be16(bytes, offset, 6); offset += 2;
    write_be16(bytes, offset, 1); offset += 2;

    write_be16(bytes, offset, 14); offset += 2;
    write_be32(bytes, offset, 13); offset += 4;
    write_be16(bytes, offset, 1); offset += 2;
    write_be16(bytes, offset, 0); offset += 2;
    write_be32(bytes, offset, 1); offset += 4;
    bytes[offset++] = 0xB1;
    write_be16(bytes, offset, 0); offset += 2;
    write_be16(bytes, offset, 0); offset += 2;

    write_be16(bytes, offset, 0); offset += 2;

    bytes.resize(offset);
    return bytes;
}

std::vector<std::uint8_t> make_minimal_dex() {
    constexpr std::uint32_t header_size = 112;
    constexpr std::uint32_t string_ids_count = 5;
    constexpr std::uint32_t type_ids_count = 2;
    constexpr std::uint32_t proto_ids_count = 1;
    constexpr std::uint32_t field_ids_count = 1;
    constexpr std::uint32_t method_ids_count = 2;
    constexpr std::uint32_t class_defs_count = 1;

    const std::uint32_t string_ids_offset = header_size;
    const std::uint32_t type_ids_offset = string_ids_offset + string_ids_count * 4;
    const std::uint32_t proto_ids_offset = type_ids_offset + type_ids_count * 4;
    const std::uint32_t field_ids_offset = proto_ids_offset + proto_ids_count * 12;
    const std::uint32_t method_ids_offset = field_ids_offset + field_ids_count * 8;
    const std::uint32_t class_defs_offset = method_ids_offset + method_ids_count * 8;

    std::uint32_t data_offset = class_defs_offset + class_defs_count * 32;
    data_offset = (data_offset + 3u) & ~3u;

    const std::uint32_t string_data_0 = data_offset;
    const std::uint32_t string_data_1 = string_data_0 + 12;
    const std::uint32_t string_data_2 = string_data_1 + 8;
    const std::uint32_t string_data_3 = string_data_2 + 4;
    const std::uint32_t string_data_4 = string_data_3 + 6;

    const std::uint32_t class_data_offset = string_data_4 + 6;
    const std::uint32_t code_item_offset = class_data_offset + 16;
    const std::uint32_t map_offset = code_item_offset + 24;
    const std::uint32_t file_size = map_offset + 4 + 8 * 12;

    std::vector<std::uint8_t> bytes(file_size, 0);

    bytes[0] = 'd'; bytes[1] = 'e'; bytes[2] = 'x'; bytes[3] = '\n';
    bytes[4] = '0'; bytes[5] = '3'; bytes[6] = '5'; bytes[7] = 0;
    write_le32(bytes, 8, 0);
    for (int i = 0; i < 20; ++i) bytes[12 + i] = static_cast<std::uint8_t>(i + 1);
    write_le32(bytes, 32, file_size);
    write_le32(bytes, 36, header_size);
    write_le32(bytes, 40, 0x12345678);
    write_le32(bytes, 44, 0);
    write_le32(bytes, 48, 0);
    write_le32(bytes, 52, map_offset);
    write_le32(bytes, 56, string_ids_count);
    write_le32(bytes, 60, string_ids_offset);
    write_le32(bytes, 64, type_ids_count);
    write_le32(bytes, 68, type_ids_offset);
    write_le32(bytes, 72, proto_ids_count);
    write_le32(bytes, 76, proto_ids_offset);
    write_le32(bytes, 80, field_ids_count);
    write_le32(bytes, 84, field_ids_offset);
    write_le32(bytes, 88, method_ids_count);
    write_le32(bytes, 92, method_ids_offset);
    write_le32(bytes, 96, class_defs_count);
    write_le32(bytes, 100, class_defs_offset);
    write_le32(bytes, 104, file_size - data_offset);
    write_le32(bytes, 108, data_offset);

    write_le32(bytes, string_ids_offset, string_data_0);
    write_le32(bytes, string_ids_offset + 4, string_data_1);
    write_le32(bytes, string_ids_offset + 8, string_data_2);
    write_le32(bytes, string_ids_offset + 12, string_data_3);
    write_le32(bytes, string_ids_offset + 16, string_data_4);

    auto write_string_data = [&](std::uint32_t addr, std::uint16_t len, const char* str) {
        bytes[addr] = static_cast<std::uint8_t>(len);
        std::memcpy(&bytes[addr + 1], str, std::strlen(str));
        bytes[addr + 1 + std::strlen(str)] = 0;
    };
    write_string_data(string_data_0, 11, "LHello;");
    write_string_data(string_data_1, 4, "<init>");
    write_string_data(string_data_2, 3, "()V");
    write_string_data(string_data_3, 5, "value");
    write_string_data(string_data_4, 1, "I");

    write_le32(bytes, type_ids_offset, 0);
    write_le32(bytes, type_ids_offset + 4, 4);

    write_le32(bytes, proto_ids_offset, 2);
    write_le32(bytes, proto_ids_offset + 4, 1);
    write_le32(bytes, proto_ids_offset + 8, 0);

    write_le16(bytes, field_ids_offset, 0);
    write_le16(bytes, field_ids_offset + 2, 1);
    write_le32(bytes, field_ids_offset + 4, 3);

    write_le16(bytes, method_ids_offset, 0);
    write_le16(bytes, method_ids_offset + 2, 0);
    write_le32(bytes, method_ids_offset + 4, 1);
    write_le16(bytes, method_ids_offset + 8, 0);
    write_le16(bytes, method_ids_offset + 10, 0);
    write_le32(bytes, method_ids_offset + 12, 1);

    write_le32(bytes, class_defs_offset, 0);
    write_le32(bytes, class_defs_offset + 4, 0x0001);
    write_le32(bytes, class_defs_offset + 8, 0xFFFFFFFF);
    write_le32(bytes, class_defs_offset + 12, 0);
    write_le32(bytes, class_defs_offset + 16, 0xFFFFFFFF);
    write_le32(bytes, class_defs_offset + 20, 0);
    write_le32(bytes, class_defs_offset + 24, class_data_offset);
    write_le32(bytes, class_defs_offset + 28, 0);

    bytes[class_data_offset] = 0;
    bytes[class_data_offset + 1] = 0;
    bytes[class_data_offset + 2] = 1;
    bytes[class_data_offset + 3] = 0;
    bytes[class_data_offset + 4] = 0;
    bytes[class_data_offset + 5] = 1;
    bytes[class_data_offset + 6] =
        static_cast<std::uint8_t>((code_item_offset & 0x7FU) | 0x80U);
    bytes[class_data_offset + 7] =
        static_cast<std::uint8_t>(code_item_offset >> 7U);

    write_le16(bytes, code_item_offset, 2);
    write_le16(bytes, code_item_offset + 2, 1);
    write_le16(bytes, code_item_offset + 4, 2);
    write_le16(bytes, code_item_offset + 6, 0);
    write_le32(bytes, code_item_offset + 8, 0);
    write_le32(bytes, code_item_offset + 12, 2);
    write_le16(bytes, code_item_offset + 16, 0x000E);
    write_le16(bytes, code_item_offset + 18, 0x0000);

    write_le32(bytes, map_offset, 8);
    auto write_map_item = [&](std::uint32_t idx, std::uint16_t type, std::uint32_t size, std::uint32_t off) {
        const auto base = map_offset + 4 + idx * 12;
        write_le16(bytes, base, type);
        write_le16(bytes, base + 2, 0);
        write_le32(bytes, base + 4, size);
        write_le32(bytes, base + 8, off);
    };
    write_map_item(0, 0x0000, 1, 0);
    write_map_item(1, 0x0001, string_ids_count, string_ids_offset);
    write_map_item(2, 0x0002, type_ids_count, type_ids_offset);
    write_map_item(3, 0x0003, proto_ids_count, proto_ids_offset);
    write_map_item(4, 0x0004, field_ids_count, field_ids_offset);
    write_map_item(5, 0x0005, method_ids_count, method_ids_offset);
    write_map_item(6, 0x0006, class_defs_count, class_defs_offset);
    write_map_item(7, 0x1000, 1, map_offset);

    return bytes;
}

std::vector<std::uint8_t> make_runtime_container(
    bool vdex, std::uint32_t dex_count) {
    require(dex_count != 0, "runtime container requires a DEX member");
    const auto dex = make_minimal_dex();
    std::vector<std::uint8_t> bytes(64 + dex.size() * dex_count, 0);
    if (vdex) {
        bytes[0] = 'v';
        bytes[1] = 'd';
        bytes[2] = 'e';
        bytes[3] = 'x';
        bytes[4] = '0';
        bytes[5] = '1';
        bytes[6] = '9';
    } else {
        bytes[0] = 'o';
        bytes[1] = 'a';
        bytes[2] = 't';
        bytes[3] = '\n';
        bytes[4] = '0';
        bytes[5] = '7';
        bytes[6] = '9';
    }
    for (std::uint32_t index = 0; index < dex_count; ++index)
        std::copy(dex.begin(), dex.end(),
            bytes.begin() + 64 + dex.size() * index);
    return bytes;
}

void test_classfile_reader() {
    std::cout << "  [classfile] Building synthetic classfile fixture..." << std::endl;
    auto classfile_bytes = make_minimal_classfile();
    temp_fixture_t fixture(classfile_bytes, ".class");
    auto provider = fixture.open_provider();

    std::cout << "  [classfile] Reading managed artifact..." << std::endl;
    auto artifact = require_value(
        mr::read_classfile(*provider), "read_classfile failed");

    require(artifact.kind == mr::managed_artifact_kind_t::java_classfile,
            "classfile artifact kind mismatch");
    require(artifact.schema_version == mr::managed_reader_schema_version &&
            artifact.valid(), "classfile artifact schema is invalid");
    require(artifact.module_identity.artifact_offset == 0 &&
            artifact.module_identity.artifact_size == provider->size() &&
            artifact.module_identity.artifact_ordinal == 0,
            "classfile artifact provider range is invalid");
    require(artifact.module_identity.artifact_hash ==
            require_value(provider->compute_content_sha256(),
                "classfile provider hash failed"),
            "classfile artifact hash does not bind the provider");
    require(!artifact.module_identity.assembly_name.empty(),
            "classfile module identity assembly_name is empty");
    require(artifact.module_identity.assembly_name == "Hello",
            "classfile module identity assembly_name mismatch");
    require(!artifact.types.empty(), "classfile should have at least one type");
    require(artifact.types[0].type_name == "Hello", "classfile type name mismatch");
    require(artifact.types[0].base_type_name.value_or("") == "java/lang/Object",
            "classfile base type mismatch");

    require(artifact.methods.size() >= 2, "classfile should have at least 2 methods");
    require(artifact.methods[0].method_name == "<init>" || artifact.methods[1].method_name == "<init>",
            "classfile should have an <init> method");
    require(artifact.methods[0].has_body || artifact.methods[1].has_body,
            "classfile should have a method with a body");

    require(!artifact.fields.empty(), "classfile should have at least one field");
    require(artifact.fields[0].field_name == "value", "classfile field name mismatch");
    require(artifact.fields[0].field_signature == "I", "classfile field signature mismatch");

    require(!artifact.member_references.empty(),
            "classfile should have cross-member references");
    bool has_method_ref = false;
    for (const auto& ref : artifact.member_references) {
        if (ref.kind == mr::managed_reference_kind_t::method_reference) {
            has_method_ref = true;
            break;
        }
    }
    require(has_method_ref, "classfile should have method references");

    bool has_code_range = false;
    bool has_exception_region = false;
    for (const auto& range : artifact.code_ranges) {
        has_code_range = true;
        require(range.size > 0, "classfile code range should have non-zero size");
    }
    require(has_code_range, "classfile should have code ranges");

    for (const auto& region : artifact.exception_regions) {
        has_exception_region = true;
        require(region.end_offset > region.start_offset,
                "classfile exception region end should be after start");
        require(region.is_catch_all, "classfile exception region should be catch-all");
    }
    require(has_exception_region, "classfile should have at least one exception region");

    std::cout << "  [classfile] Building JVM decompiler entity identity..." << std::endl;
    auto jvm_identity = mr::build_jvm_entity_identity(artifact, 0);
    require(jvm_identity.class_internal_name == "Hello",
            "JVM entity identity class name mismatch");
    require(!jvm_identity.method_name.empty(), "JVM entity identity method name is empty");

    auto jvm_key = mr::build_jvm_entity_key(artifact, 0);
    require(jvm_key.kind == decompiler_entity_kind_t::jvm_method,
            "JVM entity key kind mismatch");
    require(jvm_key.format == format_id_t::classfile,
            "JVM entity key format mismatch");
    require(jvm_key.architecture == architecture_id_t::jvm_bytecode,
            "JVM entity key architecture mismatch");
    require(jvm_key.mode == architecture_mode_t::jvm,
            "JVM entity key mode mismatch");

    std::cout << "  [classfile] PASS" << std::endl;
}

void test_dex_reader() {
    std::cout << "  [dex] Building synthetic DEX fixture..." << std::endl;
    auto dex_bytes = make_minimal_dex();
    temp_fixture_t fixture(dex_bytes, ".dex");
    auto provider = fixture.open_provider();

    std::cout << "  [dex] Reading managed artifact..." << std::endl;
    auto artifact = require_value(
        mr::read_dex(*provider), "read_dex failed");

    require(artifact.kind == mr::managed_artifact_kind_t::dex,
            "DEX artifact kind mismatch");
    require(artifact.schema_version == mr::managed_reader_schema_version &&
            artifact.valid(), "DEX artifact schema is invalid");
    require(artifact.module_identity.artifact_offset == 0 &&
            artifact.module_identity.artifact_size == provider->size() &&
            artifact.module_identity.artifact_ordinal == 0,
            "DEX artifact provider range is invalid");
    require(artifact.module_identity.artifact_hash ==
            require_value(provider->compute_content_sha256(),
                "DEX provider hash failed"),
            "DEX artifact hash does not bind the provider");
    require(!artifact.module_identity.assembly_name.empty(),
            "DEX module identity version is empty");
    require(artifact.module_identity.version == "035",
            "DEX module identity version mismatch");

    require(!artifact.types.empty(), "DEX should have at least one type");
    require(artifact.types[0].type_name == "LHello;",
            "DEX type descriptor mismatch");

    require(!artifact.methods.empty(), "DEX should have at least one method");
    require(artifact.methods[0].declaring_type_name == "LHello;",
            "DEX method declaring type mismatch");

    require(!artifact.member_references.empty(),
            "DEX should have cross-member references");

    std::cout << "  [dex] Building Dalvik decompiler entity identity..." << std::endl;
    auto dalvik_identity = mr::build_dalvik_entity_identity(artifact, 0);
    require(dalvik_identity.class_descriptor == "LHello;",
            "Dalvik entity identity class descriptor mismatch");
    require(!dalvik_identity.method_name.empty(),
            "Dalvik entity identity method name is empty");

    auto dalvik_key = mr::build_dalvik_entity_key(artifact, 0);
    require(dalvik_key.kind == decompiler_entity_kind_t::dalvik_method,
            "Dalvik entity key kind mismatch");
    require(dalvik_key.format == format_id_t::dex,
            "Dalvik entity key format mismatch");
    require(dalvik_key.architecture == architecture_id_t::dalvik_bytecode,
            "Dalvik entity key architecture mismatch");
    require(dalvik_key.mode == architecture_mode_t::dalvik,
            "Dalvik entity key mode mismatch");

    std::cout << "  [dex] PASS" << std::endl;
}

void test_cli_metadata_identity_builders() {
    std::cout << "  [cli] Testing CLI identity builders with synthetic metadata..." << std::endl;

    mr::managed_artifact_t artifact;
    artifact.kind = mr::managed_artifact_kind_t::cli_metadata;
    artifact.module_identity.kind = mr::managed_artifact_kind_t::cli_metadata;
    artifact.module_identity.assembly_name = "TestAssembly";
    artifact.module_identity.module_name = "TestModule";
    artifact.module_identity.version = "1.0.0.0";
    artifact.module_identity.artifact_size = 4096;

    mr::managed_type_identity_t type;
    type.type_name = "TestClass";
    type.namespace_name = "Test";
    type.fully_qualified_name = "Test.TestClass";
    type.metadata_token = 0x02000001;
    type.generic_arity = 0;
    artifact.types.push_back(std::move(type));

    mr::managed_method_identity_t method;
    method.declaring_type_name = "Test.TestClass";
    method.method_name = "TestMethod";
    method.method_signature = "()V";
    method.metadata_token = 0x06000001;
    method.method_index = 0;
    method.generic_arity = 0;
    method.has_body = true;
    method.code_offset = 0x1000;
    method.code_size = 32;
    artifact.methods.push_back(std::move(method));

    mr::managed_field_identity_t field;
    field.declaring_type_name = "Test.TestClass";
    field.field_name = "TestField";
    field.field_signature = "I";
    field.metadata_token = 0x04000001;
    field.field_index = 0;
    artifact.fields.push_back(std::move(field));

    mr::managed_member_reference_t ref;
    ref.kind = mr::managed_reference_kind_t::method_reference;
    ref.declaring_type_name = "Test.OtherClass";
    ref.member_name = "OtherMethod";
    ref.member_signature = "()I";
    ref.reference_token = 0x0A000001;
    artifact.member_references.push_back(std::move(ref));

    mr::managed_code_range_t code_range;
    code_range.offset = 0x1000;
    code_range.size = 32;
    code_range.max_stack = 2;
    code_range.method_token = 0x06000001;
    code_range.is_fat_format = true;
    artifact.code_ranges.push_back(std::move(code_range));

    mr::managed_exception_region_t exc;
    exc.start_offset = 0;
    exc.end_offset = 16;
    exc.handler_offset = 16;
    exc.method_token = 0x06000001;
    exc.is_finally = true;
    artifact.exception_regions.push_back(std::move(exc));

    mr::managed_annotation_t ann;
    ann.annotation_type = "TestAttribute";
    ann.parent_token = 0x06000001;
    ann.is_runtime_visible = true;
    artifact.annotations.push_back(std::move(ann));

    mr::managed_resource_t res;
    res.name = "TestResource";
    res.offset = 0x2000;
    res.size = 256;
    res.flags = 0;
    artifact.resources.push_back(std::move(res));

    auto cli_identity = mr::build_cli_entity_identity(artifact, 0);
    require(cli_identity.assembly_identity == "TestAssembly",
            "CLI entity identity assembly mismatch");
    require(cli_identity.module_name == "TestModule",
            "CLI entity identity module name mismatch");
    require(cli_identity.metadata_token == 0x06000001,
            "CLI entity identity metadata token mismatch");
    require(cli_identity.declaring_type == "Test.TestClass",
            "CLI entity identity declaring type mismatch");
    require(cli_identity.method_name == "TestMethod",
            "CLI entity identity method name mismatch");
    require(cli_identity.method_signature == "()V",
            "CLI entity identity method signature mismatch");
    require(cli_identity.generic_arity == 0,
            "CLI entity identity generic arity mismatch");

    auto cli_key = mr::build_cli_entity_key(artifact, 0);
    require(cli_key.kind == decompiler_entity_kind_t::cli_method,
            "CLI entity key kind mismatch");
    require(cli_key.format == format_id_t::pe32_plus,
            "CLI entity key format mismatch");

    std::string token_str = mr::format_cli_token(0x06000001);
    require(token_str == "0x06000001", "CLI token format mismatch");

    std::cout << "  [cli] PASS" << std::endl;
}

void test_malformed_index_handling() {
    std::cout << "  [malformed] Testing malformed index handling..." << std::endl;

    std::vector<std::uint8_t> bad_bytes(16, 0);
    bad_bytes[0] = 0xCA; bad_bytes[1] = 0xFE;
    bad_bytes[2] = 0xBA; bad_bytes[3] = 0xBE;
    temp_fixture_t bad_fixture(bad_bytes, ".class");
    auto provider = bad_fixture.open_provider();

    auto result = mr::read_classfile(*provider);
    require(!result, "malformed classfile should fail to parse");
    require(result.error().code != workspace_error_code_t::none,
            "malformed classfile should produce an error code");

    std::vector<std::uint8_t> bad_dex(16, 0);
    bad_dex[0] = 'd'; bad_dex[1] = 'e'; bad_dex[2] = 'x'; bad_dex[3] = '\n';
    bad_dex[4] = '0'; bad_dex[5] = '3'; bad_dex[6] = '5'; bad_dex[7] = 0;
    temp_fixture_t bad_dex_fixture(bad_dex, ".dex");
    auto dex_provider = bad_dex_fixture.open_provider();

    auto dex_result = mr::read_dex(*dex_provider);
    require(!dex_result, "malformed DEX should fail to parse");
    require(dex_result.error().code != workspace_error_code_t::none,
            "malformed DEX should produce an error code");

    std::cout << "  [malformed] PASS" << std::endl;
}

void test_duplicate_identity_detection() {
    std::cout << "  [duplicate] Testing duplicate identity detection..." << std::endl;

    auto classfile_bytes = make_classfile_with_duplicate_methods();
    temp_fixture_t fixture(classfile_bytes, ".class");
    auto provider = fixture.open_provider();

    auto artifact = require_value(
        mr::read_classfile(*provider), "read_classfile should succeed for duplicate-method fixture");

    require(!artifact.duplicate_identities.empty(),
            "reader should detect duplicate method identities");

    bool found_method_dup = false;
    for (const auto& dup : artifact.duplicate_identities) {
        if (dup.description.find("Duplicate JVM method identity") != std::string::npos) {
            found_method_dup = true;
            require(!dup.identity_key.empty(),
                    "duplicate method identity key should not be empty");
            break;
        }
    }
    require(found_method_dup,
            "reader should populate duplicate_identities with duplicate method identity");

    std::cout << "  [duplicate] PASS" << std::endl;
}

void test_cancellation() {
    std::cout << "  [cancel] Testing cancellation..." << std::endl;

    auto classfile_bytes = make_minimal_classfile();
    temp_fixture_t cf_fixture(classfile_bytes, ".class");
    auto cf_provider = cf_fixture.open_provider();
    cancellation_source_t cancel_source;
    cancel_source.request_cancel();

    auto result = mr::read_classfile(*cf_provider, {}, cancel_source.token());
    require(!result, "cancelled classfile read should fail");
    require(result.error().code == workspace_error_code_t::cancelled ||
            result.error().code == workspace_error_code_t::deadline_exceeded,
            "cancelled read should produce cancellation error");

    mr::managed_reader_limits_t invalid_limits;
    invalid_limits.max_methods = 0;
    auto invalid = mr::read_classfile(*cf_provider, invalid_limits);
    require(!invalid &&
            invalid.error().code == workspace_error_code_t::invalid_argument,
            "invalid managed reader limits should fail before parsing");

    std::cout << "  [cancel] PASS" << std::endl;
}

void test_oat_vdex_version_detection() {
    std::cout << "  [oat/vdex] Testing OAT/VDEX version detection..." << std::endl;

    std::vector<std::uint8_t> oat_bytes(16, 0);
    oat_bytes[0] = 'o'; oat_bytes[1] = 'a'; oat_bytes[2] = 't'; oat_bytes[3] = '\n';
    oat_bytes[4] = '0'; oat_bytes[5] = '7'; oat_bytes[6] = '9'; oat_bytes[7] = 0;
    temp_fixture_t oat_fixture(oat_bytes, ".oat");
    auto oat_provider = oat_fixture.open_provider();

    auto oat_container = require_value(
        ::aida::analysis::detect_dex_container(*oat_provider),
        "OAT container detection failed");
    require(oat_container.kind == ::aida::analysis::dex_container_kind_t::oat,
            "OAT container kind mismatch");
    require(oat_container.version == "079", "OAT version mismatch");

    std::vector<std::uint8_t> vdex_bytes(16, 0);
    vdex_bytes[0] = 'v'; vdex_bytes[1] = 'd'; vdex_bytes[2] = 'e'; vdex_bytes[3] = 'x';
    vdex_bytes[4] = '0'; vdex_bytes[5] = '1'; vdex_bytes[6] = '9'; vdex_bytes[7] = 0;
    temp_fixture_t vdex_fixture(vdex_bytes, ".vdex");
    auto vdex_provider = vdex_fixture.open_provider();

    auto vdex_container = require_value(
        ::aida::analysis::detect_dex_container(*vdex_provider),
        "VDEX container detection failed");
    require(vdex_container.kind == ::aida::analysis::dex_container_kind_t::vdex,
            "VDEX container kind mismatch");
    require(vdex_container.version == "019", "VDEX version mismatch");

    std::cout << "  [oat/vdex] PASS" << std::endl;
}

void test_managed_artifact_dispatch() {
    std::cout << "  [dispatch] Testing managed artifact auto-detection..." << std::endl;

    auto classfile_bytes = make_minimal_classfile();
    temp_fixture_t cf_fixture(classfile_bytes, ".class");
    auto cf_provider = cf_fixture.open_provider();
    auto cf_result = mr::read_managed_artifact(*cf_provider);
    require(cf_result.has_value(), "auto-detection should detect classfile format");
    require(cf_result.value().kind == mr::managed_artifact_kind_t::java_classfile,
            "auto-detection classfile kind mismatch");

    auto dex_bytes = make_minimal_dex();
    temp_fixture_t dex_fixture(dex_bytes, ".dex");
    auto dex_provider = dex_fixture.open_provider();
    auto dex_result = mr::read_managed_artifact(*dex_provider);
    require(dex_result.has_value(), "auto-detection should detect DEX format");
    require(dex_result.value().kind == mr::managed_artifact_kind_t::dex,
            "auto-detection DEX kind mismatch");

    std::vector<std::uint8_t> unknown_bytes = {0xDE, 0xAD, 0xBE, 0xEF};
    temp_fixture_t unk_fixture(unknown_bytes, ".bin");
    auto unk_provider = unk_fixture.open_provider();
    auto unk_result = mr::read_managed_artifact(*unk_provider);
    require(!unk_result, "auto-detection should reject unknown format");

    std::cout << "  [dispatch] PASS" << std::endl;
}

void test_multidex_container() {
    std::cout << "  [multidex] Testing multidex container reading..." << std::endl;

    auto dex_bytes = make_minimal_dex();
    temp_fixture_t fixture(dex_bytes, ".dex");
    auto provider = fixture.open_provider();

    auto multidex_result = mr::read_multidex_container(*provider);
    require(multidex_result.has_value(), "multidex container read should succeed for single DEX");
    require(multidex_result.value().valid(), "multidex should be valid");
    require(!multidex_result.value().artifacts.empty(),
            "multidex should have at least one artifact");
    require(multidex_result.value().artifacts[0].kind == mr::managed_artifact_kind_t::dex,
            "multidex single DEX artifact kind mismatch");

    const auto oat_bytes = make_runtime_container(false, 2);
    temp_fixture_t oat_fixture(oat_bytes, ".oat");
    auto oat_provider = oat_fixture.open_provider();
    auto oat = require_value(mr::read_multidex_container(*oat_provider),
        "OAT multidex read failed");
    require(oat.container_kind == mr::managed_artifact_kind_t::oat,
            "OAT container kind mismatch");
    require(oat.artifacts.size() == 2 && oat.embedded_offsets.size() == 2,
            "OAT container did not publish every DEX member");
    const auto dex_size = dex_bytes.size();
    for (std::uint32_t index = 0; index < oat.artifacts.size(); ++index) {
        const auto& artifact = oat.artifacts[index];
        require(artifact.kind == mr::managed_artifact_kind_t::oat &&
                artifact.module_identity.kind == mr::managed_artifact_kind_t::oat,
                "OAT member kind mismatch");
        require(artifact.module_identity.artifact_ordinal == index &&
                artifact.module_identity.artifact_offset ==
                    64 + dex_size * index &&
                artifact.module_identity.artifact_size == dex_size,
                "OAT member identity range mismatch");
        require(!artifact.module_identity.artifact_hash.empty(),
                "OAT member hash is empty");
        const auto identity = mr::build_dalvik_entity_identity(artifact, 0);
        require(identity.dex_ordinal == index &&
                identity.dex_hash == artifact.module_identity.artifact_hash,
                "OAT member decompiler identity is not artifact-bound");
        require(mr::build_dalvik_entity_key(artifact, 0).format ==
                format_id_t::oat,
                "OAT member decompiler key lost its container format");
    }
    auto ambiguous = mr::read_dex(*oat_provider);
    require(!ambiguous &&
            ambiguous.error().code == workspace_error_code_t::target_ambiguous,
            "single-artifact OAT API did not reject multiple members");
    auto detected = mr::read_managed_artifact(*oat_provider);
    require(!detected &&
            detected.error().code == workspace_error_code_t::target_ambiguous,
            "managed dispatcher did not reject ambiguous OAT members");
    mr::managed_reader_limits_t one_member_limit;
    one_member_limit.max_dex_files = 1;
    auto limited = mr::read_multidex_container(
        *oat_provider, one_member_limit);
    require(!limited &&
            limited.error().code == workspace_error_code_t::limit_exceeded,
            "OAT DEX member limit did not fail closed");

    const auto vdex_bytes = make_runtime_container(true, 1);
    temp_fixture_t vdex_fixture(vdex_bytes, ".vdex");
    auto vdex_provider = vdex_fixture.open_provider();
    auto vdex = require_value(mr::read_multidex_container(*vdex_provider),
        "VDEX member read failed");
    require(vdex.container_kind == mr::managed_artifact_kind_t::vdex &&
            vdex.artifacts.size() == 1 &&
            vdex.artifacts[0].kind == mr::managed_artifact_kind_t::vdex &&
            vdex.artifacts[0].module_identity.artifact_offset == 64,
            "VDEX member publication mismatch");

    std::cout << "  [multidex] PASS" << std::endl;
}

void test_managed_entity_publication() {
    std::cout << "  [binding] Testing generation-bound entity publication..." << std::endl;

    const auto classfile_bytes = make_minimal_classfile();
    temp_fixture_t classfile_fixture(classfile_bytes, ".class");
    auto classfile_provider = classfile_fixture.open_provider();
    auto classfile_identity = make_fixture_identity(
        classfile_provider, format_id_t::classfile,
        architecture_id_t::jvm_bytecode, architecture_mode_t::jvm,
        abi_id_t::jvm, endian_t::big, "c03-managed-binding-classfile");
    auto classfile_workspace = open_fixture_workspace(
        classfile_identity, classfile_provider);
    auto classfile_managed = require_value(
        build_managed_artifact_publication(
            *classfile_identity, *classfile_provider, {},
            classfile_workspace->generation(),
            classfile_workspace->analysis_revision(),
            classfile_workspace->overlay_revision()),
        "classfile managed publication failed");
    require(classfile_managed && classfile_managed->artifacts().size() == 1 &&
            classfile_managed->methods().size() >= 2,
            "classfile managed publication is incomplete");
    auto published = classfile_workspace->publish_managed_artifacts(
        classfile_workspace->generation(),
        classfile_workspace->analysis_revision(), classfile_managed, true);
    require(published.has_value(),
            "classfile managed publication was not atomically installed");
    auto classfile_publication = classfile_workspace->analysis_publication();
    require(classfile_publication &&
            classfile_publication->analysis_revision == 1 &&
            classfile_publication->managed_artifacts &&
            classfile_publication->managed_artifacts->analysis_revision == 1 &&
            classfile_publication->managed_artifacts->reader_schema_version ==
                mr::managed_reader_schema_version &&
            classfile_publication->managed_artifacts->reader_limits.max_methods ==
                mr::managed_reader_limits_t{}.max_methods &&
            classfile_publication->managed_artifacts->records ==
                classfile_managed->records &&
            classfile_publication->coherent_with(*classfile_identity),
            "classfile managed publication revision was not rebound");
    const auto classfile_body = std::find_if(
        classfile_publication->managed_artifacts->methods().begin(),
        classfile_publication->managed_artifacts->methods().end(),
        [](const managed_method_binding_record_t& method) {
            return method.has_body;
        });
    require(classfile_body !=
            classfile_publication->managed_artifacts->methods().end(),
            "classfile publication has no method body");
    decompiler_entity_locator_t classfile_token;
    classfile_token.token = classfile_body->entity_token;
    classfile_token.artifact_ordinal = 0;
    classfile_token.expected_kind = decompiler_entity_kind_t::jvm_method;
    auto classfile_binding = require_value(
        resolve_generation_bound_entity(
            *classfile_identity, *classfile_publication, classfile_token),
        "classfile token resolution failed");
    require(classfile_binding.entity == classfile_body->entity &&
            classfile_binding.generation == classfile_publication->generation &&
            classfile_binding.analysis_revision ==
                classfile_publication->analysis_revision &&
            classfile_binding.artifact_hash ==
                classfile_publication->managed_artifacts->artifacts()[0].artifact_hash,
            "classfile entity binding is not revision and artifact bound");
    require(validate_generation_bound_entity(
        *classfile_identity, *classfile_publication,
        classfile_binding).has_value(),
        "classfile entity binding validation failed");
    decompiler_entity_locator_t classfile_address;
    classfile_address.address = classfile_body->provider_code_offset;
    classfile_address.expected_kind = decompiler_entity_kind_t::jvm_method;
    auto address_binding = require_value(
        resolve_generation_bound_entity(
            *classfile_identity, *classfile_publication, classfile_address),
        "classfile address resolution failed");
    require(address_binding.entity == classfile_binding.entity,
            "classfile token and address resolution disagree");
    const auto jvm_provider = make_fixture_provider(
        decompiler_provider_id_t::jvm_ssa, "aida-jvm-ssa");
    auto jvm_capture = require_value(capture_jvm_entity_input(
        *classfile_publication, classfile_binding, jvm_provider),
        "JVM entity capture failed");
    require(jvm_capture->entity == classfile_binding.entity &&
            jvm_capture->workspace_generation == classfile_binding.generation &&
            !jvm_capture->context.class_internal_name.empty() &&
            !jvm_capture->context.method_name.empty() &&
            !jvm_capture->context.code.empty(),
            "JVM capture did not preserve entity and method input");
    auto classfile_snapshot = require_value(capture_managed_artifact_snapshot(
        *classfile_publication, classfile_binding,
        classfile_provider->size()),
        "classfile artifact snapshot capture failed");
    require(classfile_snapshot->size() == classfile_bytes.size() &&
            (*classfile_snapshot)[0] == 0xCA &&
            (*classfile_snapshot)[1] == 0xFE &&
            (*classfile_snapshot)[2] == 0xBA &&
            (*classfile_snapshot)[3] == 0xBE,
            "classfile artifact snapshot did not preserve exact bytes");
    auto snapshot_limited = capture_managed_artifact_snapshot(
        *classfile_publication, classfile_binding,
        classfile_provider->size() - 1);
    require(!snapshot_limited &&
            snapshot_limited.error().code == workspace_error_code_t::limit_exceeded,
            "managed artifact snapshot budget did not fail closed");
    auto invalid_capture_binding = classfile_binding;
    invalid_capture_binding.artifact_index =
        (std::numeric_limits<std::uint32_t>::max)();
    auto invalid_capture = capture_jvm_entity_input(
        *classfile_publication, invalid_capture_binding, jvm_provider);
    require(!invalid_capture &&
            invalid_capture.error().code == workspace_error_code_t::invalid_argument,
            "JVM capture did not reject an invalid artifact index");

    auto stale_binding = classfile_binding;
    ++stale_binding.analysis_revision;
    auto stale = validate_generation_bound_entity(
        *classfile_identity, *classfile_publication, stale_binding);
    require(!stale && stale.error().code == workspace_error_code_t::target_stale,
            "stale classfile binding did not fail closed");
    auto cross_architecture_binding = classfile_binding;
    cross_architecture_binding.entity.architecture = architecture_id_t::x86_64;
    cross_architecture_binding.entity.mode = architecture_mode_t::x86_64;
    auto cross_architecture = validate_generation_bound_entity(
        *classfile_identity, *classfile_publication,
        cross_architecture_binding);
    require(!cross_architecture &&
            cross_architecture.error().code == workspace_error_code_t::target_stale,
            "cross-architecture classfile binding did not fail closed");
    decompiler_entity_locator_t invalid_locator;
    invalid_locator.token = classfile_body->entity_token;
    invalid_locator.address = classfile_body->provider_code_offset;
    auto invalid = resolve_generation_bound_entity(
        *classfile_identity, *classfile_publication, invalid_locator);
    require(!invalid &&
            invalid.error().code == workspace_error_code_t::invalid_argument,
            "mixed token/address locator was not rejected");
    decompiler_entity_locator_t wrong_artifact = classfile_token;
    wrong_artifact.artifact_ordinal = 99;
    auto absent = resolve_generation_bound_entity(
        *classfile_identity, *classfile_publication, wrong_artifact);
    require(!absent &&
            absent.error().code == workspace_error_code_t::target_not_found,
            "missing artifact selector did not return deterministic not-found");

    auto ambiguous_managed = std::make_shared<managed_artifact_publication_t>(
        *classfile_publication->managed_artifacts);
    auto ambiguous_records = std::make_shared<managed_artifact_record_index_t>(
        *ambiguous_managed->records);
    ambiguous_records->methods[1].entity_token =
        ambiguous_records->methods[0].entity_token;
    ambiguous_managed->records = std::static_pointer_cast<
        const managed_artifact_record_index_t>(ambiguous_records);
    auto ambiguous_publication = make_fixture_publication(
        classfile_identity, classfile_provider,
        std::static_pointer_cast<const managed_artifact_publication_t>(
            ambiguous_managed));
    decompiler_entity_locator_t ambiguous_locator;
    ambiguous_locator.token = ambiguous_managed->methods()[0].entity_token;
    ambiguous_locator.expected_kind = decompiler_entity_kind_t::jvm_method;
    auto ambiguous = resolve_generation_bound_entity(
        *classfile_identity, *ambiguous_publication, ambiguous_locator);
    require(!ambiguous &&
            ambiguous.error().code == workspace_error_code_t::target_ambiguous,
            "duplicate managed token did not report ambiguity");

    mr::managed_reader_limits_t method_limit;
    method_limit.max_methods = 1;
    auto limited = build_managed_artifact_publication(
        *classfile_identity, *classfile_provider, {}, 1, 0, 0,
        method_limit);
    require(!limited &&
            limited.error().code == workspace_error_code_t::limit_exceeded,
            "managed entity method budget did not fail closed");
    cancellation_source_t cancelled_source;
    cancelled_source.request_cancel();
    auto cancelled = build_managed_artifact_publication(
        *classfile_identity, *classfile_provider, {}, 1, 0, 0, {},
        cancelled_source.token());
    require(!cancelled &&
            cancelled.error().code == workspace_error_code_t::cancelled,
            "managed entity admission did not honor cancellation");
    const auto next_generation = require_value(
        classfile_workspace->begin_new_generation(),
        "classfile generation advance failed");
    auto next_publication = classfile_workspace->analysis_publication();
    require(next_generation == 2 && next_publication &&
            next_publication->generation == next_generation &&
            next_publication->analysis_revision == 0 &&
            next_publication->managed_artifacts &&
            next_publication->managed_artifacts->records ==
                classfile_publication->managed_artifacts->records &&
            next_publication->managed_artifacts->generation == next_generation &&
            next_publication->managed_artifacts->analysis_revision == 0 &&
            next_publication->coherent_with(*classfile_identity),
            "managed record index was not immutably rebound to the new generation");
    auto retired_binding = validate_generation_bound_entity(
        *classfile_identity, *next_publication, classfile_binding);
    require(!retired_binding &&
            retired_binding.error().code == workspace_error_code_t::target_stale,
            "retired generation binding remained valid after generation advance");

    const auto dex_bytes = make_minimal_dex();
    temp_fixture_t dex_fixture(dex_bytes, ".dex");
    auto dex_provider = dex_fixture.open_provider();
    auto dex_identity = make_fixture_identity(
        dex_provider, format_id_t::dex,
        architecture_id_t::dalvik_bytecode, architecture_mode_t::dalvik,
        abi_id_t::dalvik, endian_t::little, "c03-managed-binding-dex");
    auto dex_workspace = open_fixture_workspace(dex_identity, dex_provider);
    auto dex_managed = require_value(build_managed_artifact_publication(
        *dex_identity, *dex_provider, {}, dex_workspace->generation(),
        dex_workspace->analysis_revision(), dex_workspace->overlay_revision()),
        "DEX managed publication failed");
    require(dex_managed && !dex_managed->methods().empty(),
            "DEX managed publication is empty");
    published = dex_workspace->publish_managed_artifacts(
        dex_workspace->generation(), dex_workspace->analysis_revision(),
        dex_managed, true);
    require(published.has_value(),
            "DEX managed publication was not atomically installed");
    auto dex_publication = dex_workspace->analysis_publication();
    const auto dex_body = std::find_if(
        dex_publication->managed_artifacts->methods().begin(),
        dex_publication->managed_artifacts->methods().end(),
        [](const managed_method_binding_record_t& method) {
            return method.has_body;
        });
    require(dex_body != dex_publication->managed_artifacts->methods().end(),
            "DEX publication has no method body");
    decompiler_entity_locator_t dex_locator;
    dex_locator.token = dex_body->entity_token;
    dex_locator.artifact_ordinal = 0;
    dex_locator.expected_kind = decompiler_entity_kind_t::dalvik_method;
    auto dex_binding = require_value(resolve_generation_bound_entity(
        *dex_identity, *dex_publication, dex_locator),
        "DEX token resolution failed");
    const auto dalvik_provider = make_fixture_provider(
        decompiler_provider_id_t::dalvik_ssa, "aida-dalvik-ssa");
    auto dalvik_capture = require_value(capture_dalvik_entity_input(
        *dex_publication, dex_binding, dalvik_provider),
        "Dalvik entity capture failed");
    require(dalvik_capture->request.entity == dex_binding.entity &&
            dalvik_capture->request.workspace_generation ==
                dex_binding.generation &&
            !dalvik_capture->code_units.empty() &&
            !dalvik_capture->class_descriptor.empty() &&
            !dalvik_capture->method_name.empty(),
            "Dalvik capture did not preserve entity and code input");

    const auto oat_bytes = make_runtime_container(false, 2);
    temp_fixture_t oat_fixture(oat_bytes, ".oat");
    auto oat_provider = oat_fixture.open_provider();
    auto oat_identity = make_fixture_identity(
        oat_provider, format_id_t::oat,
        architecture_id_t::dalvik_bytecode, architecture_mode_t::dalvik,
        abi_id_t::dalvik, endian_t::little, "c03-managed-binding-oat");
    auto oat_managed = require_value(build_managed_artifact_publication(
        *oat_identity, *oat_provider, {}, 1, 1, 0),
        "OAT managed publication failed");
    require(oat_managed && oat_managed->artifacts().size() == 2,
            "OAT managed publication omitted a DEX member");
    auto oat_snapshot = std::make_shared<analysis_snapshot_t>();
    oat_snapshot->binary_id = oat_identity->binary_id();
    oat_snapshot->load_profile_hash = oat_identity->load_profile_hash();
    oat_snapshot->generation = 1;
    oat_snapshot->analysis_revision = 1;
    auto oat_publication = std::make_shared<analysis_publication_t>(
        std::static_pointer_cast<const analysis_snapshot_t>(oat_snapshot),
        std::static_pointer_cast<const byte_provider_t>(oat_provider), nullptr,
        workspace_readiness_t::provider_ready, oat_managed);
    require(oat_publication->coherent_with(*oat_identity),
            "OAT managed publication is incoherent");
    decompiler_entity_locator_t oat_ambiguous_locator;
    oat_ambiguous_locator.token = oat_managed->methods().front().entity_token;
    oat_ambiguous_locator.expected_kind =
        decompiler_entity_kind_t::dalvik_method;
    auto oat_ambiguous = resolve_generation_bound_entity(
        *oat_identity, *oat_publication, oat_ambiguous_locator);
    require(!oat_ambiguous &&
            oat_ambiguous.error().code == workspace_error_code_t::target_ambiguous,
            "OAT cross-member token ambiguity was not reported");
    oat_ambiguous_locator.artifact_ordinal = 1;
    auto oat_binding = require_value(resolve_generation_bound_entity(
        *oat_identity, *oat_publication, oat_ambiguous_locator),
        "OAT artifact-qualified token resolution failed");
    require(oat_binding.artifact_index == 1 &&
            oat_binding.artifact_hash == oat_managed->artifacts()[1].artifact_hash,
            "OAT entity did not bind the selected artifact");
    auto oat_capture = require_value(capture_dalvik_entity_input(
        *oat_publication, oat_binding, dalvik_provider),
        "OAT Dalvik entity capture failed");
    require(!oat_capture->code_units.empty() &&
            oat_capture->request.entity == oat_binding.entity,
            "OAT Dalvik capture did not use the selected artifact");

    std::cout << "  [binding] PASS" << std::endl;
}

void test_artifact_name_functions() {
    std::cout << "  [names] Testing artifact kind name functions..." << std::endl;

    require(std::string(mr::managed_artifact_kind_name(mr::managed_artifact_kind_t::cli_metadata)) == "cli-metadata",
            "cli-metadata name mismatch");
    require(std::string(mr::managed_artifact_kind_name(mr::managed_artifact_kind_t::java_classfile)) == "java-classfile",
            "java-classfile name mismatch");
    require(std::string(mr::managed_artifact_kind_name(mr::managed_artifact_kind_t::dex)) == "dex",
            "dex name mismatch");
    require(std::string(mr::managed_artifact_kind_name(mr::managed_artifact_kind_t::oat)) == "oat",
            "oat name mismatch");
    require(std::string(mr::managed_artifact_kind_name(mr::managed_artifact_kind_t::vdex)) == "vdex",
            "vdex name mismatch");
    require(std::string(mr::managed_artifact_kind_name(mr::managed_artifact_kind_t::multidex_container)) == "multidex-container",
            "multidex-container name mismatch");

    require(std::string(mr::managed_reference_kind_name(mr::managed_reference_kind_t::type_reference)) == "type-reference",
            "type-reference name mismatch");
    require(std::string(mr::managed_reference_kind_name(mr::managed_reference_kind_t::method_reference)) == "method-reference",
            "method-reference name mismatch");
    require(std::string(mr::managed_reference_kind_name(mr::managed_reference_kind_t::field_reference)) == "field-reference",
            "field-reference name mismatch");
    require(std::string(mr::managed_reference_kind_name(mr::managed_reference_kind_t::assembly_reference)) == "assembly-reference",
            "assembly-reference name mismatch");

    std::cout << "  [names] PASS" << std::endl;
}

}

void run_managed_reader_harness() {
    std::cout << "=== C03-B11 Managed Artifact Reader Harness ===" << std::endl;

    std::cout << "[1/10] Classfile reader test..." << std::endl;
    test_classfile_reader();

    std::cout << "[2/10] DEX reader test..." << std::endl;
    test_dex_reader();

    std::cout << "[3/10] CLI metadata identity builder test..." << std::endl;
    test_cli_metadata_identity_builders();

    std::cout << "[4/10] Malformed index handling test..." << std::endl;
    test_malformed_index_handling();

    std::cout << "[5/10] Duplicate identity detection test..." << std::endl;
    test_duplicate_identity_detection();

    std::cout << "[6/10] Cancellation test..." << std::endl;
    test_cancellation();

    std::cout << "[7/10] OAT/VDEX version detection test..." << std::endl;
    test_oat_vdex_version_detection();

    std::cout << "[8/10] Managed artifact auto-detection test..." << std::endl;
    test_managed_artifact_dispatch();

    std::cout << "[9/10] Multidex container test..." << std::endl;
    test_multidex_container();

    std::cout << "[10/10] Managed entity publication test..." << std::endl;
    test_managed_entity_publication();

    test_artifact_name_functions();

    std::cout << "=== C03-B11 All tests passed ===" << std::endl;
}

}
