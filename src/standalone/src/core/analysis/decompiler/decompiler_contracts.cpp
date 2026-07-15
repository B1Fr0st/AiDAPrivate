#include "decompiler_contracts.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <iterator>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <utility>

namespace aida::analysis {
namespace {

constexpr std::uint32_t k_magic_entity = 0x31454b44U;
constexpr std::uint32_t k_magic_coordinate = 0x31434b44U;
constexpr std::uint32_t k_magic_provider_ir = 0x31504b44U;
constexpr std::uint32_t k_magic_hir = 0x31484b44U;
constexpr std::uint32_t k_magic_type_graph = 0x31544b44U;
constexpr std::uint32_t k_magic_ast = 0x31414b44U;
constexpr std::uint32_t k_magic_document = 0x31444b44U;
constexpr std::uint32_t k_magic_diagnostic = 0x31474b44U;
constexpr std::uint32_t k_magic_cache = 0x31564b44U;
constexpr std::uint32_t k_magic_worker = 0x31574b44U;
constexpr std::uint32_t k_max_collection_entries = 1U << 20;
constexpr std::uint32_t k_max_string_bytes = 64U << 20;

class canonical_writer_t final {
public:
    void u8(std::uint8_t value) { bytes_.push_back(static_cast<char>(value)); }

    void u16(std::uint16_t value)
    {
        for (std::size_t index = 0; index < sizeof(value); ++index)
            u8(static_cast<std::uint8_t>(value >> (index * 8U)));
    }

    void u32(std::uint32_t value)
    {
        for (std::size_t index = 0; index < sizeof(value); ++index)
            u8(static_cast<std::uint8_t>(value >> (index * 8U)));
    }

    void u64(std::uint64_t value)
    {
        for (std::size_t index = 0; index < sizeof(value); ++index)
            u8(static_cast<std::uint8_t>(value >> (index * 8U)));
    }

    void boolean(bool value) { u8(value ? 1U : 0U); }

    void string(const std::string& value)
    {
        if (value.size() > k_max_string_bytes)
            throw std::invalid_argument("contract string exceeds serialization limit");
        u32(static_cast<std::uint32_t>(value.size()));
        bytes_.append(value);
    }

    void digest(const sha256_digest_t& value)
    {
        bytes_.append(reinterpret_cast<const char*>(value.bytes.data()), value.bytes.size());
    }

    std::string take() { return std::move(bytes_); }

private:
    std::string bytes_;
};

class canonical_reader_t final {
public:
    explicit canonical_reader_t(std::string_view value) : value_(value) {}

    bool u8(std::uint8_t& value)
    {
        if (remaining() < 1)
            return false;
        value = static_cast<std::uint8_t>(value_[offset_++]);
        return true;
    }

    bool u16(std::uint16_t& value)
    {
        std::uint64_t temporary = 0;
        if (!unsigned_value(temporary, sizeof(value)))
            return false;
        value = static_cast<std::uint16_t>(temporary);
        return true;
    }

    bool u32(std::uint32_t& value)
    {
        std::uint64_t temporary = 0;
        if (!unsigned_value(temporary, sizeof(value)))
            return false;
        value = static_cast<std::uint32_t>(temporary);
        return true;
    }

    bool u64(std::uint64_t& value) { return unsigned_value(value, sizeof(value)); }

    bool boolean(bool& value)
    {
        std::uint8_t raw = 0;
        if (!u8(raw) || raw > 1)
            return false;
        value = raw != 0;
        return true;
    }

    bool string(std::string& value)
    {
        std::uint32_t length = 0;
        if (!u32(length) || length > k_max_string_bytes || remaining() < length)
            return false;
        value.assign(value_.data() + offset_, length);
        offset_ += length;
        return true;
    }

    bool digest(sha256_digest_t& value)
    {
        if (remaining() < value.bytes.size())
            return false;
        std::memcpy(value.bytes.data(), value_.data() + offset_, value.bytes.size());
        offset_ += value.bytes.size();
        return true;
    }

    bool complete() const noexcept { return offset_ == value_.size(); }

private:
    bool unsigned_value(std::uint64_t& value, std::size_t width)
    {
        if (remaining() < width)
            return false;
        value = 0;
        for (std::size_t index = 0; index < width; ++index)
            value |= static_cast<std::uint64_t>(static_cast<std::uint8_t>(value_[offset_++])) << (index * 8U);
        return true;
    }

    std::size_t remaining() const noexcept { return value_.size() - offset_; }

    std::string_view value_;
    std::size_t offset_ = 0;
};

template <typename T>
void write_optional(canonical_writer_t& writer, const std::optional<T>& value, void (*write_value)(canonical_writer_t&, const T&))
{
    writer.boolean(value.has_value());
    if (value)
        write_value(writer, *value);
}

template <typename T>
bool read_optional(canonical_reader_t& reader, std::optional<T>& value, bool (*read_value)(canonical_reader_t&, T&))
{
    bool present = false;
    if (!reader.boolean(present))
        return false;
    if (!present) {
        value.reset();
        return true;
    }
    T decoded;
    if (!read_value(reader, decoded))
        return false;
    value = std::move(decoded);
    return true;
}

template <typename T, typename Write>
void write_vector(canonical_writer_t& writer, const std::vector<T>& value, Write&& write_value)
{
    if (value.size() > k_max_collection_entries)
        throw std::invalid_argument("contract collection exceeds serialization limit");
    writer.u32(static_cast<std::uint32_t>(value.size()));
    for (const auto& entry : value)
        write_value(writer, entry);
}

template <typename T, typename Read>
bool read_vector(canonical_reader_t& reader, std::vector<T>& value, Read&& read_value)
{
    std::uint32_t count = 0;
    if (!reader.u32(count) || count > k_max_collection_entries)
        return false;
    value.clear();
    value.reserve(count);
    for (std::uint32_t index = 0; index < count; ++index) {
        T entry;
        if (!read_value(reader, entry))
            return false;
        value.push_back(std::move(entry));
    }
    return true;
}

template <typename Enum>
void write_enum(canonical_writer_t& writer, Enum value)
{
    using raw_t = std::underlying_type_t<Enum>;
    if constexpr (sizeof(raw_t) == 1)
        writer.u8(static_cast<std::uint8_t>(value));
    else if constexpr (sizeof(raw_t) == 2)
        writer.u16(static_cast<std::uint16_t>(value));
    else
        writer.u32(static_cast<std::uint32_t>(value));
}

template <typename Enum>
bool read_enum(canonical_reader_t& reader, Enum& value)
{
    using raw_t = std::underlying_type_t<Enum>;
    raw_t raw{};
    if constexpr (sizeof(raw_t) == 1) {
        std::uint8_t encoded = 0;
        if (!reader.u8(encoded))
            return false;
        raw = static_cast<raw_t>(encoded);
    } else if constexpr (sizeof(raw_t) == 2) {
        std::uint16_t encoded = 0;
        if (!reader.u16(encoded))
            return false;
        raw = static_cast<raw_t>(encoded);
    } else {
        std::uint32_t encoded = 0;
        if (!reader.u32(encoded))
            return false;
        raw = static_cast<raw_t>(encoded);
    }
    value = static_cast<Enum>(raw);
    return true;
}

void write_address(canonical_writer_t& writer, const address_t& value)
{
    write_enum(writer, value.space);
    writer.u64(value.value);
    write_enum(writer, value.architecture);
    write_enum(writer, value.mode);
}

bool read_address(canonical_reader_t& reader, address_t& value)
{
    return read_enum(reader, value.space) && reader.u64(value.value) &&
        read_enum(reader, value.architecture) && read_enum(reader, value.mode);
}

void write_address_range(canonical_writer_t& writer, const decompiler_address_range_t& value)
{
    write_address(writer, value.begin);
    write_address(writer, value.end);
}

bool read_address_range(canonical_reader_t& reader, decompiler_address_range_t& value)
{
    return read_address(reader, value.begin) && read_address(reader, value.end);
}

void write_token_range(canonical_writer_t& writer, const decompiler_token_range_t& value)
{
    writer.u32(value.begin);
    writer.u32(value.end);
}

bool read_token_range(canonical_reader_t& reader, decompiler_token_range_t& value)
{
    return reader.u32(value.begin) && reader.u32(value.end);
}

void write_instruction_range(canonical_writer_t& writer, const decompiler_instruction_range_t& value)
{
    writer.u64(value.first_instruction_id);
    writer.u64(value.last_instruction_id);
}

bool read_instruction_range(canonical_reader_t& reader, decompiler_instruction_range_t& value)
{
    return reader.u64(value.first_instruction_id) && reader.u64(value.last_instruction_id);
}

void write_source_origin(canonical_writer_t& writer, const decompiler_source_origin_t& value)
{
    writer.digest(value.source_artifact_hash);
    writer.string(value.source_path);
    writer.u32(value.first_line);
    writer.u32(value.first_column);
    writer.u32(value.last_line);
    writer.u32(value.last_column);
}

bool read_source_origin(canonical_reader_t& reader, decompiler_source_origin_t& value)
{
    return reader.digest(value.source_artifact_hash) && reader.string(value.source_path) &&
        reader.u32(value.first_line) && reader.u32(value.first_column) &&
        reader.u32(value.last_line) && reader.u32(value.last_column);
}

void write_entity(canonical_writer_t& writer, const decompiler_entity_key_t& value)
{
    writer.u32(value.schema_version);
    write_enum(writer, value.kind);
    write_enum(writer, value.format);
    write_enum(writer, value.architecture);
    write_enum(writer, value.mode);
    write_enum(writer, value.endian);
    writer.u8(static_cast<std::uint8_t>(value.identity.index()));
    std::visit([&writer](const auto& identity) {
        using identity_t = std::decay_t<decltype(identity)>;
        if constexpr (std::is_same_v<identity_t, native_decompiler_entity_identity_t>) {
            writer.u64(identity.function_id);
            write_address(writer, identity.entry);
            write_address(writer, identity.end);
            writer.digest(identity.function_bytes_hash);
            writer.string(identity.canonical_symbol);
        } else if constexpr (std::is_same_v<identity_t, cli_decompiler_entity_identity_t>) {
            writer.digest(identity.module_hash);
            writer.string(identity.assembly_identity);
            writer.string(identity.module_name);
            writer.u32(identity.metadata_token);
            writer.string(identity.declaring_type);
            writer.string(identity.method_name);
            writer.string(identity.method_signature);
            writer.u32(identity.generic_arity);
        } else if constexpr (std::is_same_v<identity_t, jvm_decompiler_entity_identity_t>) {
            writer.digest(identity.class_artifact_hash);
            writer.string(identity.class_internal_name);
            writer.string(identity.method_name);
            writer.string(identity.method_descriptor);
            writer.u32(identity.method_index);
            writer.u32(identity.code_offset);
        } else {
            writer.digest(identity.dex_hash);
            writer.u32(identity.dex_ordinal);
            writer.string(identity.class_descriptor);
            writer.string(identity.method_name);
            writer.string(identity.prototype);
            writer.u32(identity.method_id);
            writer.u32(identity.code_item_offset);
        }
    }, value.identity);
}

bool read_entity(canonical_reader_t& reader, decompiler_entity_key_t& value)
{
    std::uint8_t variant_index = 0;
    if (!reader.u32(value.schema_version) || !read_enum(reader, value.kind) ||
        !read_enum(reader, value.format) || !read_enum(reader, value.architecture) ||
        !read_enum(reader, value.mode) || !read_enum(reader, value.endian) || !reader.u8(variant_index))
        return false;
    switch (variant_index) {
    case 0: {
        native_decompiler_entity_identity_t identity;
        if (!reader.u64(identity.function_id) || !read_address(reader, identity.entry) ||
            !read_address(reader, identity.end) || !reader.digest(identity.function_bytes_hash) ||
            !reader.string(identity.canonical_symbol))
            return false;
        value.identity = std::move(identity);
        return true;
    }
    case 1: {
        cli_decompiler_entity_identity_t identity;
        if (!reader.digest(identity.module_hash) || !reader.string(identity.assembly_identity) ||
            !reader.string(identity.module_name) || !reader.u32(identity.metadata_token) ||
            !reader.string(identity.declaring_type) || !reader.string(identity.method_name) ||
            !reader.string(identity.method_signature) || !reader.u32(identity.generic_arity))
            return false;
        value.identity = std::move(identity);
        return true;
    }
    case 2: {
        jvm_decompiler_entity_identity_t identity;
        if (!reader.digest(identity.class_artifact_hash) || !reader.string(identity.class_internal_name) ||
            !reader.string(identity.method_name) || !reader.string(identity.method_descriptor) ||
            !reader.u32(identity.method_index) || !reader.u32(identity.code_offset))
            return false;
        value.identity = std::move(identity);
        return true;
    }
    case 3: {
        dalvik_decompiler_entity_identity_t identity;
        if (!reader.digest(identity.dex_hash) || !reader.u32(identity.dex_ordinal) ||
            !reader.string(identity.class_descriptor) || !reader.string(identity.method_name) ||
            !reader.string(identity.prototype) || !reader.u32(identity.method_id) ||
            !reader.u32(identity.code_item_offset))
            return false;
        value.identity = std::move(identity);
        return true;
    }
    default:
        return false;
    }
}

void write_coordinate(canonical_writer_t& writer, const source_coordinate_t& value)
{
    write_enum(writer, value.layer);
    writer.u64(value.workspace_generation);
    write_entity(writer, value.entity);
    write_optional(writer, value.address_range, write_address_range);
    write_optional(writer, value.token_range, write_token_range);
    write_optional(writer, value.instruction_range, write_instruction_range);
    write_optional(writer, value.document_range, write_token_range);
    write_optional(writer, value.source_origin, write_source_origin);
}

bool read_coordinate(canonical_reader_t& reader, source_coordinate_t& value)
{
    return read_enum(reader, value.layer) && reader.u64(value.workspace_generation) &&
        read_entity(reader, value.entity) && read_optional(reader, value.address_range, read_address_range) &&
        read_optional(reader, value.token_range, read_token_range) &&
        read_optional(reader, value.instruction_range, read_instruction_range) &&
        read_optional(reader, value.document_range, read_token_range) &&
        read_optional(reader, value.source_origin, read_source_origin);
}

void write_diagnostic(canonical_writer_t& writer, const decompiler_diagnostic_t& value)
{
    write_enum(writer, value.severity);
    write_enum(writer, value.code);
    writer.string(value.localization_key);
    write_vector(writer, value.localization_arguments, [](canonical_writer_t& nested, const std::string& argument) {
        nested.string(argument);
    });
    write_optional(writer, value.coordinate, write_coordinate);
    writer.u8(value.confidence);
    writer.boolean(value.retryable);
    writer.u32(value.ordinal);
}

bool read_diagnostic(canonical_reader_t& reader, decompiler_diagnostic_t& value)
{
    return read_enum(reader, value.severity) && read_enum(reader, value.code) &&
        reader.string(value.localization_key) &&
        read_vector(reader, value.localization_arguments, [](canonical_reader_t& nested, std::string& argument) {
            return nested.string(argument);
        }) &&
        read_optional(reader, value.coordinate, read_coordinate) && reader.u8(value.confidence) &&
        reader.boolean(value.retryable) && reader.u32(value.ordinal);
}

void write_unknown(canonical_writer_t& writer, const decompiler_unknown_t& value)
{
    write_enum(writer, value.reason);
    writer.string(value.stable_token);
    write_coordinate(writer, value.coordinate);
    writer.u8(value.confidence);
    write_enum(writer, value.provenance);
}

bool read_unknown(canonical_reader_t& reader, decompiler_unknown_t& value)
{
    return read_enum(reader, value.reason) && reader.string(value.stable_token) &&
        read_coordinate(reader, value.coordinate) && reader.u8(value.confidence) &&
        read_enum(reader, value.provenance);
}

void write_provider(canonical_writer_t& writer, const decompiler_provider_identity_t& value)
{
    write_enum(writer, value.provider);
    writer.string(value.provider_name);
    writer.string(value.provider_version);
    writer.digest(value.provider_binary_hash);
    writer.string(value.worker_build_id);
    writer.digest(value.worker_build_hash);
}

bool read_provider(canonical_reader_t& reader, decompiler_provider_identity_t& value)
{
    return read_enum(reader, value.provider) && reader.string(value.provider_name) &&
        reader.string(value.provider_version) && reader.digest(value.provider_binary_hash) &&
        reader.string(value.worker_build_id) && reader.digest(value.worker_build_hash);
}

void write_language(canonical_writer_t& writer, const decompiler_language_identity_t& value)
{
    writer.string(value.language_id);
    writer.string(value.language_version);
    writer.string(value.compiler_spec_id);
    writer.digest(value.language_spec_hash);
    write_enum(writer, value.architecture);
    write_enum(writer, value.mode);
    write_enum(writer, value.endian);
}

bool read_language(canonical_reader_t& reader, decompiler_language_identity_t& value)
{
    return reader.string(value.language_id) && reader.string(value.language_version) &&
        reader.string(value.compiler_spec_id) && reader.digest(value.language_spec_hash) &&
        read_enum(reader, value.architecture) && read_enum(reader, value.mode) &&
        read_enum(reader, value.endian);
}

void write_provider_value(canonical_writer_t& writer, const provider_ir_value_t& value)
{
    writer.u64(value.id);
    write_enum(writer, value.opcode);
    writer.u64(value.type_id);
    write_vector(writer, value.operand_ids, [](canonical_writer_t& nested, std::uint64_t id) { nested.u64(id); });
    writer.string(value.stable_immediate);
    writer.string(value.stable_symbol);
    write_coordinate(writer, value.coordinate);
    writer.u8(value.confidence);
    write_enum(writer, value.provenance);
}

bool read_provider_value(canonical_reader_t& reader, provider_ir_value_t& value)
{
    return reader.u64(value.id) && read_enum(reader, value.opcode) && reader.u64(value.type_id) &&
        read_vector(reader, value.operand_ids, [](canonical_reader_t& nested, std::uint64_t& id) {
            return nested.u64(id);
        }) &&
        reader.string(value.stable_immediate) && reader.string(value.stable_symbol) &&
        read_coordinate(reader, value.coordinate) && reader.u8(value.confidence) &&
        read_enum(reader, value.provenance);
}

void write_provider_block(canonical_writer_t& writer, const provider_ir_block_t& value)
{
    writer.u64(value.id);
    const auto write_id = [](canonical_writer_t& nested, std::uint64_t id) { nested.u64(id); };
    write_vector(writer, value.predecessor_ids, write_id);
    write_vector(writer, value.successor_ids, write_id);
    write_vector(writer, value.exception_successor_ids, write_id);
    write_vector(writer, value.values, write_provider_value);
    write_coordinate(writer, value.coordinate);
}

bool read_provider_block(canonical_reader_t& reader, provider_ir_block_t& value)
{
    const auto read_id = [](canonical_reader_t& nested, std::uint64_t& id) { return nested.u64(id); };
    return reader.u64(value.id) && read_vector(reader, value.predecessor_ids, read_id) &&
        read_vector(reader, value.successor_ids, read_id) &&
        read_vector(reader, value.exception_successor_ids, read_id) &&
        read_vector(reader, value.values, read_provider_value) && read_coordinate(reader, value.coordinate);
}

void write_hir_value(canonical_writer_t& writer, const hir_value_t& value)
{
    writer.u64(value.id);
    write_enum(writer, value.kind);
    writer.u64(value.type_id);
    write_vector(writer, value.operand_ids, [](canonical_writer_t& nested, std::uint64_t id) { nested.u64(id); });
    writer.string(value.stable_value);
    write_coordinate(writer, value.coordinate);
    writer.u8(value.confidence);
    write_enum(writer, value.provenance);
}

bool read_hir_value(canonical_reader_t& reader, hir_value_t& value)
{
    return reader.u64(value.id) && read_enum(reader, value.kind) && reader.u64(value.type_id) &&
        read_vector(reader, value.operand_ids, [](canonical_reader_t& nested, std::uint64_t& id) {
            return nested.u64(id);
        }) &&
        reader.string(value.stable_value) && read_coordinate(reader, value.coordinate) &&
        reader.u8(value.confidence) && read_enum(reader, value.provenance);
}

void write_hir_block(canonical_writer_t& writer, const hir_block_t& value)
{
    writer.u64(value.id);
    const auto write_id = [](canonical_writer_t& nested, std::uint64_t id) { nested.u64(id); };
    write_vector(writer, value.predecessor_ids, write_id);
    write_vector(writer, value.successor_ids, write_id);
    write_vector(writer, value.exception_successor_ids, write_id);
    write_vector(writer, value.values, write_hir_value);
    write_coordinate(writer, value.coordinate);
}

bool read_hir_block(canonical_reader_t& reader, hir_block_t& value)
{
    const auto read_id = [](canonical_reader_t& nested, std::uint64_t& id) { return nested.u64(id); };
    return reader.u64(value.id) && read_vector(reader, value.predecessor_ids, read_id) &&
        read_vector(reader, value.successor_ids, read_id) &&
        read_vector(reader, value.exception_successor_ids, read_id) &&
        read_vector(reader, value.values, read_hir_value) && read_coordinate(reader, value.coordinate);
}

void write_hir_variable(canonical_writer_t& writer, const hir_variable_t& value)
{
    writer.u64(value.id);
    writer.string(value.stable_name);
    writer.u64(value.type_id);
    write_coordinate(writer, value.coordinate);
    writer.u8(value.confidence);
    write_enum(writer, value.provenance);
}

bool read_hir_variable(canonical_reader_t& reader, hir_variable_t& value)
{
    return reader.u64(value.id) && reader.string(value.stable_name) && reader.u64(value.type_id) &&
        read_coordinate(reader, value.coordinate) && reader.u8(value.confidence) &&
        read_enum(reader, value.provenance);
}

void write_type_node(canonical_writer_t& writer, const decompiler_type_node_t& value)
{
    writer.u64(value.id);
    write_enum(writer, value.kind);
    writer.string(value.canonical_name);
    writer.string(value.display_name);
    writer.boolean(value.byte_size.has_value());
    if (value.byte_size)
        writer.u64(*value.byte_size);
    writer.u32(value.alignment);
    writer.boolean(value.is_signed);
    writer.u8(value.confidence);
    write_enum(writer, value.provenance);
    write_vector(writer, value.coordinates, write_coordinate);
}

bool read_type_node(canonical_reader_t& reader, decompiler_type_node_t& value)
{
    bool has_size = false;
    if (!reader.u64(value.id) || !read_enum(reader, value.kind) || !reader.string(value.canonical_name) ||
        !reader.string(value.display_name) || !reader.boolean(has_size))
        return false;
    if (has_size) {
        std::uint64_t size = 0;
        if (!reader.u64(size))
            return false;
        value.byte_size = size;
    } else {
        value.byte_size.reset();
    }
    return reader.u32(value.alignment) && reader.boolean(value.is_signed) && reader.u8(value.confidence) &&
        read_enum(reader, value.provenance) && read_vector(reader, value.coordinates, read_coordinate);
}

void write_type_edge(canonical_writer_t& writer, const decompiler_type_edge_t& value)
{
    writer.u64(value.source_type_id);
    writer.u64(value.target_type_id);
    write_enum(writer, value.kind);
    writer.string(value.stable_name);
    writer.boolean(value.byte_offset.has_value());
    if (value.byte_offset)
        writer.u64(*value.byte_offset);
    writer.u32(value.ordinal);
    writer.u8(value.confidence);
    write_enum(writer, value.provenance);
}

bool read_type_edge(canonical_reader_t& reader, decompiler_type_edge_t& value)
{
    bool has_offset = false;
    if (!reader.u64(value.source_type_id) || !reader.u64(value.target_type_id) ||
        !read_enum(reader, value.kind) || !reader.string(value.stable_name) || !reader.boolean(has_offset))
        return false;
    if (has_offset) {
        std::uint64_t offset = 0;
        if (!reader.u64(offset))
            return false;
        value.byte_offset = offset;
    } else {
        value.byte_offset.reset();
    }
    return reader.u32(value.ordinal) && reader.u8(value.confidence) && read_enum(reader, value.provenance);
}

void write_ast_node(canonical_writer_t& writer, const typed_pseudocode_ast_node_t& value)
{
    writer.u64(value.id);
    write_enum(writer, value.kind);
    writer.u64(value.type_id);
    write_vector(writer, value.child_ids, [](canonical_writer_t& nested, std::uint64_t id) { nested.u64(id); });
    writer.string(value.stable_text);
    write_coordinate(writer, value.coordinate);
    writer.u8(value.confidence);
    write_enum(writer, value.provenance);
}

bool read_ast_node(canonical_reader_t& reader, typed_pseudocode_ast_node_t& value)
{
    return reader.u64(value.id) && read_enum(reader, value.kind) && reader.u64(value.type_id) &&
        read_vector(reader, value.child_ids, [](canonical_reader_t& nested, std::uint64_t& id) {
            return nested.u64(id);
        }) &&
        reader.string(value.stable_text) && read_coordinate(reader, value.coordinate) &&
        reader.u8(value.confidence) && read_enum(reader, value.provenance);
}

void write_document_token(canonical_writer_t& writer, const decompiler_document_token_t& value)
{
    write_enum(writer, value.kind);
    write_token_range(writer, value.range);
    writer.u64(value.ast_node_id);
}

bool read_document_token(canonical_reader_t& reader, decompiler_document_token_t& value)
{
    return read_enum(reader, value.kind) && read_token_range(reader, value.range) && reader.u64(value.ast_node_id);
}

void write_document_source_map(canonical_writer_t& writer, const decompiler_document_source_map_t& value)
{
    write_token_range(writer, value.document_range);
    write_vector(writer, value.coordinates, write_coordinate);
}

bool read_document_source_map(canonical_reader_t& reader, decompiler_document_source_map_t& value)
{
    return read_token_range(reader, value.document_range) && read_vector(reader, value.coordinates, read_coordinate);
}

void write_renderer(canonical_writer_t& writer, const decompiler_renderer_settings_t& value)
{
    writer.u32(value.schema_version);
    writer.string(value.style_id);
    writer.u32(value.indentation_spaces);
    writer.boolean(value.emit_type_annotations);
    writer.boolean(value.emit_provenance_annotations);
    writer.boolean(value.emit_unknown_tokens);
}

bool read_renderer(canonical_reader_t& reader, decompiler_renderer_settings_t& value)
{
    return reader.u32(value.schema_version) && reader.string(value.style_id) &&
        reader.u32(value.indentation_spaces) && reader.boolean(value.emit_type_annotations) &&
        reader.boolean(value.emit_provenance_annotations) && reader.boolean(value.emit_unknown_tokens);
}

void write_profile(canonical_writer_t& writer, const decompiler_profile_budget_t& value)
{
    write_enum(writer, value.profile);
    writer.u32(value.schema_version);
    writer.u64(value.max_wall_clock_ms);
    writer.u64(value.max_cpu_ms);
    writer.u64(value.max_memory_bytes);
    writer.u64(value.max_provider_ir_nodes);
    writer.u64(value.max_hir_nodes);
    writer.u64(value.max_ast_nodes);
    writer.u32(value.max_semantic_queries);
    writer.boolean(value.semantic_proofs_enabled);
}

bool read_profile(canonical_reader_t& reader, decompiler_profile_budget_t& value)
{
    return read_enum(reader, value.profile) && reader.u32(value.schema_version) &&
        reader.u64(value.max_wall_clock_ms) && reader.u64(value.max_cpu_ms) &&
        reader.u64(value.max_memory_bytes) && reader.u64(value.max_provider_ir_nodes) &&
        reader.u64(value.max_hir_nodes) && reader.u64(value.max_ast_nodes) &&
        reader.u32(value.max_semantic_queries) && reader.boolean(value.semantic_proofs_enabled);
}

void write_chunk_fingerprint(canonical_writer_t& writer, const decompiler_chunk_fingerprint_t& value)
{
    write_address(writer, value.begin);
    write_address(writer, value.end);
    writer.digest(value.bytes_hash);
}

bool read_chunk_fingerprint(canonical_reader_t& reader, decompiler_chunk_fingerprint_t& value)
{
    return read_address(reader, value.begin) && read_address(reader, value.end) && reader.digest(value.bytes_hash);
}

void write_dependency(canonical_writer_t& writer, const decompiler_dependency_version_t& value)
{
    writer.string(value.name);
    writer.string(value.version);
    writer.digest(value.content_hash);
}

bool read_dependency(canonical_reader_t& reader, decompiler_dependency_version_t& value)
{
    return reader.string(value.name) && reader.string(value.version) && reader.digest(value.content_hash);
}

void write_cache_key(canonical_writer_t& writer, const decompiler_pipeline_cache_key_t& value)
{
    writer.u32(value.schema_version);
    write_enum(writer, value.stage);
    writer.string(value.workspace_id);
    writer.u64(value.workspace_generation);
    writer.u64(value.analysis_revision);
    write_entity(writer, value.entity);
    write_provider(writer, value.provider);
    writer.u32(value.worker_protocol_version);
    writer.digest(value.worker_protocol_hash);
    write_language(writer, value.language);
    writer.digest(value.loader_layout_hash);
    writer.digest(value.function_bytes_hash);
    write_vector(writer, value.chunk_fingerprints, write_chunk_fingerprint);
    writer.u64(value.metadata_revision);
    writer.u64(value.type_graph_revision);
    writer.u64(value.overlay_revision);
    write_profile(writer, value.profile);
    writer.u32(value.provider_ir_schema_version);
    writer.u32(value.hir_schema_version);
    writer.u32(value.type_graph_schema_version);
    writer.u32(value.ast_schema_version);
    writer.u32(value.document_schema_version);
    write_renderer(writer, value.renderer);
    write_vector(writer, value.dependencies, write_dependency);
}

bool read_cache_key(canonical_reader_t& reader, decompiler_pipeline_cache_key_t& value)
{
    return reader.u32(value.schema_version) && read_enum(reader, value.stage) &&
        reader.string(value.workspace_id) && reader.u64(value.workspace_generation) &&
        reader.u64(value.analysis_revision) && read_entity(reader, value.entity) &&
        read_provider(reader, value.provider) && reader.u32(value.worker_protocol_version) &&
        reader.digest(value.worker_protocol_hash) && read_language(reader, value.language) &&
        reader.digest(value.loader_layout_hash) && reader.digest(value.function_bytes_hash) &&
        read_vector(reader, value.chunk_fingerprints, read_chunk_fingerprint) &&
        reader.u64(value.metadata_revision) && reader.u64(value.type_graph_revision) &&
        reader.u64(value.overlay_revision) && read_profile(reader, value.profile) &&
        reader.u32(value.provider_ir_schema_version) && reader.u32(value.hir_schema_version) &&
        reader.u32(value.type_graph_schema_version) && reader.u32(value.ast_schema_version) &&
        reader.u32(value.document_schema_version) && read_renderer(reader, value.renderer) &&
        read_vector(reader, value.dependencies, read_dependency);
}

void write_envelope(canonical_writer_t& writer, const decompiler_worker_envelope_t& value)
{
    writer.u32(value.protocol_version);
    write_enum(writer, value.kind);
    writer.digest(value.session_nonce_hash);
    writer.u64(value.sequence);
}

bool read_envelope(canonical_reader_t& reader, decompiler_worker_envelope_t& value)
{
    return reader.u32(value.protocol_version) && read_enum(reader, value.kind) &&
        reader.digest(value.session_nonce_hash) && reader.u64(value.sequence);
}

decompiler_diagnostic_t contract_error(decompiler_diagnostic_code_t code, std::string key)
{
    decompiler_diagnostic_t diagnostic;
    diagnostic.severity = decompiler_diagnostic_severity_t::error;
    diagnostic.code = code;
    diagnostic.localization_key = std::move(key);
    return diagnostic;
}

void append(decompiler_contract_validation_t& target, const decompiler_contract_validation_t& source)
{
    target.diagnostics.insert(target.diagnostics.end(), source.diagnostics.begin(), source.diagnostics.end());
}

bool valid_range(const decompiler_token_range_t& range) noexcept
{
    return range.begin < range.end;
}

bool valid_range(const decompiler_address_range_t& range) noexcept
{
    return range.begin.space == range.end.space && range.begin.architecture == range.end.architecture &&
        range.begin.mode == range.end.mode && range.begin.value < range.end.value;
}

bool valid_range(const decompiler_instruction_range_t& range) noexcept
{
    return range.first_instruction_id != 0 && range.first_instruction_id <= range.last_instruction_id;
}

bool same_entity(const decompiler_entity_key_t& left, const decompiler_entity_key_t& right) noexcept
{
    return left == right;
}

template <typename T, typename Id>
bool strictly_increasing_ids(const std::vector<T>& values, Id&& id) noexcept
{
    std::uint64_t previous = 0;
    for (const auto& value : values) {
        const auto current = id(value);
        if (current == 0 || current <= previous)
            return false;
        previous = current;
    }
    return true;
}

bool ordered_diagnostics(const std::vector<decompiler_diagnostic_t>& values) noexcept
{
    std::uint32_t previous = 0;
    for (const auto& value : values) {
        if (value.ordinal == 0 || value.ordinal <= previous)
            return false;
        previous = value.ordinal;
    }
    return true;
}

bool valid_provider(const decompiler_provider_identity_t& value) noexcept
{
    return !value.provider_name.empty() && !value.provider_version.empty() &&
        !value.provider_binary_hash.empty() && !value.worker_build_id.empty() && !value.worker_build_hash.empty();
}

bool valid_language(const decompiler_language_identity_t& value) noexcept
{
    return !value.language_id.empty() && !value.language_version.empty() && !value.compiler_spec_id.empty() &&
        !value.language_spec_hash.empty();
}

bool language_matches_entity(const decompiler_language_identity_t& language, const decompiler_entity_key_t& entity) noexcept
{
    switch (entity.kind) {
    case decompiler_entity_kind_t::native_function:
        return language.architecture == entity.architecture && language.mode == entity.mode && language.endian == entity.endian;
    case decompiler_entity_kind_t::jvm_method:
        return language.architecture == architecture_id_t::jvm_bytecode && language.mode == architecture_mode_t::jvm;
    case decompiler_entity_kind_t::dalvik_method:
        return language.architecture == architecture_id_t::dalvik_bytecode && language.mode == architecture_mode_t::dalvik;
    case decompiler_entity_kind_t::cli_method:
        return true;
    }
    return false;
}

bool valid_renderer(const decompiler_renderer_settings_t& value) noexcept
{
    return value.schema_version == 1 && !value.style_id.empty() && value.indentation_spaces >= 1 &&
        value.indentation_spaces <= 16;
}

bool valid_diagnostic_severity(decompiler_diagnostic_severity_t value) noexcept
{
    return value == decompiler_diagnostic_severity_t::note ||
        value == decompiler_diagnostic_severity_t::warning ||
        value == decompiler_diagnostic_severity_t::error;
}

bool valid_diagnostic_code(decompiler_diagnostic_code_t value) noexcept
{
    return value >= decompiler_diagnostic_code_t::invalid_contract &&
        value <= decompiler_diagnostic_code_t::source_map_rejected;
}

bool valid_diagnostic(const decompiler_diagnostic_t& value)
{
    return valid_diagnostic_severity(value.severity) && valid_diagnostic_code(value.code) &&
        !value.localization_key.empty() && value.confidence <= 100;
}

void append_diagnostic_validation(
    decompiler_contract_validation_t& result,
    const std::vector<decompiler_diagnostic_t>& diagnostics,
    decompiler_diagnostic_code_t malformed_code,
    const char* diagnostics_key,
    const char* diagnostic_key,
    const char* coordinate_key,
    const decompiler_entity_key_t* entity,
    std::optional<decompiler_coordinate_layer_t> expected_layer)
{
    if (!ordered_diagnostics(diagnostics))
        result.diagnostics.push_back(contract_error(malformed_code, diagnostics_key));
    for (const auto& diagnostic : diagnostics) {
        if (!valid_diagnostic(diagnostic))
            result.diagnostics.push_back(contract_error(malformed_code, diagnostic_key));
        if (!diagnostic.coordinate)
            continue;
        append(result, validate_source_coordinate(*diagnostic.coordinate));
        if ((entity && !same_entity(diagnostic.coordinate->entity, *entity)) ||
            (expected_layer && diagnostic.coordinate->layer != *expected_layer))
            result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::source_map_rejected, coordinate_key));
    }
}

bool valid_unknown(const decompiler_unknown_t& value) noexcept
{
    return !value.stable_token.empty() && value.confidence <= 100 && validate_source_coordinate(value.coordinate).valid();
}

bool is_managed_provider(decompiler_provider_id_t provider, decompiler_entity_kind_t kind) noexcept
{
    switch (kind) {
    case decompiler_entity_kind_t::native_function:
        return provider == decompiler_provider_id_t::ghidra_native;
    case decompiler_entity_kind_t::cli_method:
        return provider == decompiler_provider_id_t::ilspy_cli;
    case decompiler_entity_kind_t::jvm_method:
        return provider == decompiler_provider_id_t::jvm_ssa;
    case decompiler_entity_kind_t::dalvik_method:
        return provider == decompiler_provider_id_t::dalvik_ssa;
    }
    return false;
}

template <typename T>
decompiler_contract_decode_result_t<T> decode_failure(std::string error)
{
    decompiler_contract_decode_result_t<T> result;
    result.error = std::move(error);
    return result;
}

template <typename T, typename Decode, typename Validate>
decompiler_contract_decode_result_t<T> decode_root(const std::string& value, std::uint32_t magic, Decode&& decode, Validate&& validate)
{
    canonical_reader_t reader(value);
    std::uint32_t encoded_magic = 0;
    if (!reader.u32(encoded_magic) || encoded_magic != magic)
        return decode_failure<T>("decompiler contract magic mismatch");
    T decoded;
    if (!decode(reader, decoded) || !reader.complete())
        return decode_failure<T>("malformed decompiler contract serialization");
    const auto verification = validate(decoded);
    if (!verification.valid())
        return decode_failure<T>(verification.diagnostics.empty() ? "invalid decompiler contract" : verification.diagnostics.front().localization_key);
    decompiler_contract_decode_result_t<T> result;
    result.value = std::move(decoded);
    return result;
}

template <typename Validate>
void require_valid(const Validate& validation)
{
    if (!validation.valid())
        throw std::invalid_argument(validation.diagnostics.empty() ? "invalid decompiler contract" : validation.diagnostics.front().localization_key);
}

class sha256_t final {
public:
    sha256_t()
    {
        state_ = {0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
                  0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};
    }

    void update(const std::uint8_t* data, std::size_t length)
    {
        total_bytes_ += length;
        while (length != 0) {
            const std::size_t take = (std::min)(length, block_.size() - block_size_);
            std::memcpy(block_.data() + block_size_, data, take);
            block_size_ += take;
            data += take;
            length -= take;
            if (block_size_ == block_.size()) {
                transform(block_.data());
                block_size_ = 0;
            }
        }
    }

    sha256_digest_t finish()
    {
        const std::uint64_t bit_length = static_cast<std::uint64_t>(total_bytes_) * 8U;
        block_[block_size_++] = 0x80U;
        if (block_size_ > 56) {
            std::fill(block_.begin() + static_cast<decltype(block_)::difference_type>(block_size_), block_.end(), 0);
            transform(block_.data());
            block_size_ = 0;
        }
        std::fill(block_.begin() + static_cast<decltype(block_)::difference_type>(block_size_), block_.begin() + 56, 0);
        for (std::size_t index = 0; index < 8; ++index)
            block_[63 - index] = static_cast<std::uint8_t>(bit_length >> (index * 8U));
        transform(block_.data());
        sha256_digest_t digest;
        for (std::size_t index = 0; index < state_.size(); ++index) {
            digest.bytes[index * 4] = static_cast<std::uint8_t>(state_[index] >> 24U);
            digest.bytes[index * 4 + 1] = static_cast<std::uint8_t>(state_[index] >> 16U);
            digest.bytes[index * 4 + 2] = static_cast<std::uint8_t>(state_[index] >> 8U);
            digest.bytes[index * 4 + 3] = static_cast<std::uint8_t>(state_[index]);
        }
        return digest;
    }

private:
    static std::uint32_t rotate_right(std::uint32_t value, std::uint32_t count) noexcept
    {
        return (value >> count) | (value << (32U - count));
    }

    void transform(const std::uint8_t* block)
    {
        static constexpr std::array<std::uint32_t, 64> constants = {
            0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
            0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
            0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
            0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
            0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
            0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
            0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
            0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};
        std::array<std::uint32_t, 64> words{};
        for (std::size_t index = 0; index < 16; ++index) {
            const auto* input = block + index * 4;
            words[index] = (static_cast<std::uint32_t>(input[0]) << 24U) |
                (static_cast<std::uint32_t>(input[1]) << 16U) |
                (static_cast<std::uint32_t>(input[2]) << 8U) |
                static_cast<std::uint32_t>(input[3]);
        }
        for (std::size_t index = 16; index < words.size(); ++index) {
            const std::uint32_t s0 = rotate_right(words[index - 15], 7) ^ rotate_right(words[index - 15], 18) ^ (words[index - 15] >> 3U);
            const std::uint32_t s1 = rotate_right(words[index - 2], 17) ^ rotate_right(words[index - 2], 19) ^ (words[index - 2] >> 10U);
            words[index] = words[index - 16] + s0 + words[index - 7] + s1;
        }
        auto a = state_[0];
        auto b = state_[1];
        auto c = state_[2];
        auto d = state_[3];
        auto e = state_[4];
        auto f = state_[5];
        auto g = state_[6];
        auto h = state_[7];
        for (std::size_t index = 0; index < words.size(); ++index) {
            const std::uint32_t s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
            const std::uint32_t choose = (e & f) ^ ((~e) & g);
            const std::uint32_t temporary1 = h + s1 + choose + constants[index] + words[index];
            const std::uint32_t s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
            const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t temporary2 = s0 + majority;
            h = g;
            g = f;
            f = e;
            e = d + temporary1;
            d = c;
            c = b;
            b = a;
            a = temporary1 + temporary2;
        }
        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
    }

    std::array<std::uint32_t, 8> state_{};
    std::array<std::uint8_t, 64> block_{};
    std::size_t block_size_ = 0;
    std::size_t total_bytes_ = 0;
};

}

bool decompiler_entity_key_t::operator==(const decompiler_entity_key_t& other) const noexcept
{
    if (schema_version != other.schema_version || kind != other.kind || format != other.format ||
        architecture != other.architecture || mode != other.mode || endian != other.endian ||
        identity.index() != other.identity.index())
        return false;
    if (const auto* left = std::get_if<native_decompiler_entity_identity_t>(&identity)) {
        const auto& right = std::get<native_decompiler_entity_identity_t>(other.identity);
        return left->function_id == right.function_id && left->entry == right.entry && left->end == right.end &&
            left->function_bytes_hash == right.function_bytes_hash && left->canonical_symbol == right.canonical_symbol;
    }
    if (const auto* left = std::get_if<cli_decompiler_entity_identity_t>(&identity)) {
        const auto& right = std::get<cli_decompiler_entity_identity_t>(other.identity);
        return left->module_hash == right.module_hash && left->assembly_identity == right.assembly_identity &&
            left->module_name == right.module_name && left->metadata_token == right.metadata_token &&
            left->declaring_type == right.declaring_type && left->method_name == right.method_name &&
            left->method_signature == right.method_signature && left->generic_arity == right.generic_arity;
    }
    if (const auto* left = std::get_if<jvm_decompiler_entity_identity_t>(&identity)) {
        const auto& right = std::get<jvm_decompiler_entity_identity_t>(other.identity);
        return left->class_artifact_hash == right.class_artifact_hash &&
            left->class_internal_name == right.class_internal_name && left->method_name == right.method_name &&
            left->method_descriptor == right.method_descriptor && left->method_index == right.method_index &&
            left->code_offset == right.code_offset;
    }
    const auto& left = std::get<dalvik_decompiler_entity_identity_t>(identity);
    const auto& right = std::get<dalvik_decompiler_entity_identity_t>(other.identity);
    return left.dex_hash == right.dex_hash && left.dex_ordinal == right.dex_ordinal &&
        left.class_descriptor == right.class_descriptor && left.method_name == right.method_name &&
        left.prototype == right.prototype && left.method_id == right.method_id &&
        left.code_item_offset == right.code_item_offset;
}

bool decompiler_entity_key_t::operator<(const decompiler_entity_key_t& other) const noexcept
{
    if (schema_version != other.schema_version) return schema_version < other.schema_version;
    if (kind != other.kind) return kind < other.kind;
    if (format != other.format) return format < other.format;
    if (architecture != other.architecture) return architecture < other.architecture;
    if (mode != other.mode) return mode < other.mode;
    if (endian != other.endian) return endian < other.endian;
    if (identity.index() != other.identity.index()) return identity.index() < other.identity.index();
    if (const auto* left = std::get_if<native_decompiler_entity_identity_t>(&identity)) {
        const auto& right = std::get<native_decompiler_entity_identity_t>(other.identity);
        if (left->function_id != right.function_id) return left->function_id < right.function_id;
        if (left->entry != right.entry) return left->entry < right.entry;
        if (left->end != right.end) return left->end < right.end;
        if (left->function_bytes_hash != right.function_bytes_hash) return left->function_bytes_hash < right.function_bytes_hash;
        return left->canonical_symbol < right.canonical_symbol;
    }
    if (const auto* left = std::get_if<cli_decompiler_entity_identity_t>(&identity)) {
        const auto& right = std::get<cli_decompiler_entity_identity_t>(other.identity);
        if (left->module_hash != right.module_hash) return left->module_hash < right.module_hash;
        if (left->assembly_identity != right.assembly_identity) return left->assembly_identity < right.assembly_identity;
        if (left->module_name != right.module_name) return left->module_name < right.module_name;
        if (left->metadata_token != right.metadata_token) return left->metadata_token < right.metadata_token;
        if (left->declaring_type != right.declaring_type) return left->declaring_type < right.declaring_type;
        if (left->method_name != right.method_name) return left->method_name < right.method_name;
        if (left->method_signature != right.method_signature) return left->method_signature < right.method_signature;
        return left->generic_arity < right.generic_arity;
    }
    if (const auto* left = std::get_if<jvm_decompiler_entity_identity_t>(&identity)) {
        const auto& right = std::get<jvm_decompiler_entity_identity_t>(other.identity);
        if (left->class_artifact_hash != right.class_artifact_hash) return left->class_artifact_hash < right.class_artifact_hash;
        if (left->class_internal_name != right.class_internal_name) return left->class_internal_name < right.class_internal_name;
        if (left->method_name != right.method_name) return left->method_name < right.method_name;
        if (left->method_descriptor != right.method_descriptor) return left->method_descriptor < right.method_descriptor;
        if (left->method_index != right.method_index) return left->method_index < right.method_index;
        return left->code_offset < right.code_offset;
    }
    const auto& left = std::get<dalvik_decompiler_entity_identity_t>(identity);
    const auto& right = std::get<dalvik_decompiler_entity_identity_t>(other.identity);
    if (left.dex_hash != right.dex_hash) return left.dex_hash < right.dex_hash;
    if (left.dex_ordinal != right.dex_ordinal) return left.dex_ordinal < right.dex_ordinal;
    if (left.class_descriptor != right.class_descriptor) return left.class_descriptor < right.class_descriptor;
    if (left.method_name != right.method_name) return left.method_name < right.method_name;
    if (left.prototype != right.prototype) return left.prototype < right.prototype;
    if (left.method_id != right.method_id) return left.method_id < right.method_id;
    return left.code_item_offset < right.code_item_offset;
}

bool decompiler_contract_validation_t::valid() const noexcept
{
    return diagnostics.empty();
}

decompiler_contract_validation_t validate_decompiler_entity_key(const decompiler_entity_key_t& value)
{
    decompiler_contract_validation_t result;
    if (value.schema_version != k_decompiler_contract_schema_version) {
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::invalid_contract, "decompiler.entity.schema"));
        return result;
    }
    const auto mismatch = [&result]() {
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::invalid_contract, "decompiler.entity.identity_mismatch"));
    };
    switch (value.kind) {
    case decompiler_entity_kind_t::native_function: {
        const auto* identity = std::get_if<native_decompiler_entity_identity_t>(&value.identity);
        if (!identity || value.architecture == architecture_id_t::unknown || value.mode == architecture_mode_t::unknown ||
            identity->function_id == 0 || identity->function_bytes_hash.empty() || identity->canonical_symbol.empty() ||
            identity->entry.architecture != value.architecture || identity->entry.mode != value.mode ||
            identity->end.architecture != value.architecture || identity->end.mode != value.mode ||
            !valid_range({identity->entry, identity->end}))
            mismatch();
        break;
    }
    case decompiler_entity_kind_t::cli_method: {
        const auto* identity = std::get_if<cli_decompiler_entity_identity_t>(&value.identity);
        if (!identity || value.format == format_id_t::unknown || identity->module_hash.empty() ||
            identity->assembly_identity.empty() || identity->module_name.empty() || identity->metadata_token == 0 ||
            identity->declaring_type.empty() || identity->method_name.empty() || identity->method_signature.empty())
            mismatch();
        break;
    }
    case decompiler_entity_kind_t::jvm_method: {
        const auto* identity = std::get_if<jvm_decompiler_entity_identity_t>(&value.identity);
        if (!identity || (value.format != format_id_t::classfile && value.format != format_id_t::jar) ||
            value.architecture != architecture_id_t::jvm_bytecode || value.mode != architecture_mode_t::jvm ||
            identity->class_artifact_hash.empty() || identity->class_internal_name.empty() ||
            identity->method_name.empty() || identity->method_descriptor.empty())
            mismatch();
        break;
    }
    case decompiler_entity_kind_t::dalvik_method: {
        const auto* identity = std::get_if<dalvik_decompiler_entity_identity_t>(&value.identity);
        if (!identity || (value.format != format_id_t::dex && value.format != format_id_t::apk &&
            value.format != format_id_t::oat && value.format != format_id_t::vdex) ||
            value.architecture != architecture_id_t::dalvik_bytecode || value.mode != architecture_mode_t::dalvik ||
            identity->dex_hash.empty() || identity->class_descriptor.empty() || identity->method_name.empty() ||
            identity->prototype.empty())
            mismatch();
        break;
    }
    default:
        mismatch();
        break;
    }
    return result;
}

decompiler_contract_validation_t validate_source_coordinate(const source_coordinate_t& value)
{
    decompiler_contract_validation_t result;
    if (value.layer != decompiler_coordinate_layer_t::provider_ir && value.layer != decompiler_coordinate_layer_t::hir &&
        value.layer != decompiler_coordinate_layer_t::typed_ast && value.layer != decompiler_coordinate_layer_t::document)
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::invalid_contract, "decompiler.coordinate.layer"));
    if (value.workspace_generation == 0)
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::invalid_contract, "decompiler.coordinate.generation"));
    append(result, validate_decompiler_entity_key(value.entity));
    if (value.address_range && !valid_range(*value.address_range))
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::source_map_rejected, "decompiler.coordinate.address_range"));
    if (value.token_range && !valid_range(*value.token_range))
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::source_map_rejected, "decompiler.coordinate.token_range"));
    if (value.instruction_range && !valid_range(*value.instruction_range))
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::source_map_rejected, "decompiler.coordinate.instruction_range"));
    if (value.document_range && !valid_range(*value.document_range))
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::source_map_rejected, "decompiler.coordinate.document_range"));
    if (value.source_origin && (value.source_origin->source_artifact_hash.empty() || value.source_origin->source_path.empty() ||
        value.source_origin->first_line == 0 || value.source_origin->last_line < value.source_origin->first_line ||
        (value.source_origin->last_line == value.source_origin->first_line &&
         value.source_origin->last_column < value.source_origin->first_column)))
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::source_map_rejected, "decompiler.coordinate.source_origin"));
    if (!value.address_range && !value.token_range && !value.instruction_range && !value.document_range && !value.source_origin)
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::source_map_rejected, "decompiler.coordinate.anchor"));
    if (value.layer == decompiler_coordinate_layer_t::document && !value.document_range)
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::source_map_rejected, "decompiler.coordinate.document_anchor"));
    return result;
}

decompiler_contract_validation_t validate_provider_ir(const provider_ir_t& value)
{
    decompiler_contract_validation_t result;
    if (value.schema_version != k_provider_ir_schema_version || !valid_provider(value.provider) ||
        !valid_language(value.language) || !language_matches_entity(value.language, value.entity) ||
        !is_managed_provider(value.provider.provider, value.entity.kind) ||
        value.entry_block_id == 0 || value.blocks.empty())
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_provider_ir, "decompiler.provider_ir.header"));
    append(result, validate_decompiler_entity_key(value.entity));
    const bool ordered_blocks = strictly_increasing_ids(value.blocks, [](const provider_ir_block_t& block) { return block.id; });
    if (!ordered_blocks)
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_provider_ir, "decompiler.provider_ir.block_order"));
    const auto has_block = [&value, ordered_blocks](std::uint64_t id) {
        if (!ordered_blocks)
            return false;
        const auto iterator = std::lower_bound(value.blocks.begin(), value.blocks.end(), id,
            [](const provider_ir_block_t& block, std::uint64_t candidate) { return block.id < candidate; });
        return iterator != value.blocks.end() && iterator->id == id;
    };
    if (!has_block(value.entry_block_id))
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_provider_ir, "decompiler.provider_ir.entry_block"));
    std::uint64_t previous_value_id = 0;
    for (const auto& block : value.blocks) {
        append(result, validate_source_coordinate(block.coordinate));
        if (block.coordinate.layer != decompiler_coordinate_layer_t::provider_ir ||
            !same_entity(block.coordinate.entity, value.entity) || block.values.empty() ||
            !strictly_increasing_ids(block.values, [](const provider_ir_value_t& node) { return node.id; }))
            result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_provider_ir, "decompiler.provider_ir.block"));
        const auto valid_block_reference_list = [&has_block](const std::vector<std::uint64_t>& ids) {
            return std::is_sorted(ids.begin(), ids.end()) && std::all_of(ids.begin(), ids.end(), has_block) &&
                std::adjacent_find(ids.begin(), ids.end()) == ids.end();
        };
        if (!valid_block_reference_list(block.predecessor_ids) || !valid_block_reference_list(block.successor_ids) ||
            !valid_block_reference_list(block.exception_successor_ids))
            result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_provider_ir, "decompiler.provider_ir.edge"));
        for (const auto& node : block.values) {
            if (node.type_id == 0 || node.confidence > 100 || node.coordinate.layer != decompiler_coordinate_layer_t::provider_ir ||
                !same_entity(node.coordinate.entity, value.entity))
                result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_provider_ir, "decompiler.provider_ir.value"));
            if (node.id <= previous_value_id)
                result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_provider_ir, "decompiler.provider_ir.value_order"));
            previous_value_id = node.id;
            append(result, validate_source_coordinate(node.coordinate));
        }
    }
    for (const auto& coordinate : value.source_coordinates) {
        append(result, validate_source_coordinate(coordinate));
        if (coordinate.layer != decompiler_coordinate_layer_t::provider_ir || !same_entity(coordinate.entity, value.entity))
            result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::source_map_rejected, "decompiler.provider_ir.source_entity"));
    }
    for (const auto& unknown : value.unknowns) {
        if (!valid_unknown(unknown) || !same_entity(unknown.coordinate.entity, value.entity))
            result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_provider_ir, "decompiler.provider_ir.unknown"));
    }
    append_diagnostic_validation(result, value.diagnostics, decompiler_diagnostic_code_t::malformed_provider_ir,
        "decompiler.provider_ir.diagnostics", "decompiler.provider_ir.diagnostic",
        "decompiler.provider_ir.diagnostic_coordinate", &value.entity, decompiler_coordinate_layer_t::provider_ir);
    return result;
}

decompiler_contract_validation_t validate_hir_function(const hir_function_t& value)
{
    decompiler_contract_validation_t result;
    if (value.schema_version != k_hir_schema_version || value.provider_ir_hash.empty() || value.type_graph_revision == 0 ||
        value.return_type_id == 0 || value.blocks.empty())
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_hir, "decompiler.hir.header"));
    append(result, validate_decompiler_entity_key(value.entity));
    const auto validate_variables = [&result, &value](const std::vector<hir_variable_t>& variables, const char* key) {
        if (!strictly_increasing_ids(variables, [](const hir_variable_t& variable) { return variable.id; }))
            result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_hir, key));
        for (const auto& variable : variables) {
            if (variable.stable_name.empty() || variable.type_id == 0 || variable.confidence > 100 ||
                variable.coordinate.layer != decompiler_coordinate_layer_t::hir ||
                !same_entity(variable.coordinate.entity, value.entity))
                result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_hir, key));
            append(result, validate_source_coordinate(variable.coordinate));
        }
    };
    validate_variables(value.parameters, "decompiler.hir.parameters");
    validate_variables(value.locals, "decompiler.hir.locals");
    const bool ordered_blocks = strictly_increasing_ids(value.blocks, [](const hir_block_t& block) { return block.id; });
    if (!ordered_blocks)
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_hir, "decompiler.hir.block_order"));
    const auto has_block = [&value, ordered_blocks](std::uint64_t id) {
        if (!ordered_blocks)
            return false;
        const auto iterator = std::lower_bound(value.blocks.begin(), value.blocks.end(), id,
            [](const hir_block_t& block, std::uint64_t candidate) { return block.id < candidate; });
        return iterator != value.blocks.end() && iterator->id == id;
    };
    std::uint64_t previous_value_id = 0;
    for (const auto& block : value.blocks) {
        append(result, validate_source_coordinate(block.coordinate));
        if (block.coordinate.layer != decompiler_coordinate_layer_t::hir ||
            !same_entity(block.coordinate.entity, value.entity) || block.values.empty() ||
            !strictly_increasing_ids(block.values, [](const hir_value_t& node) { return node.id; }))
            result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_hir, "decompiler.hir.block"));
        const auto valid_block_reference_list = [&has_block](const std::vector<std::uint64_t>& ids) {
            return std::is_sorted(ids.begin(), ids.end()) && std::all_of(ids.begin(), ids.end(), has_block) &&
                std::adjacent_find(ids.begin(), ids.end()) == ids.end();
        };
        if (!valid_block_reference_list(block.predecessor_ids) || !valid_block_reference_list(block.successor_ids) ||
            !valid_block_reference_list(block.exception_successor_ids))
            result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_hir, "decompiler.hir.edge"));
        for (const auto& node : block.values) {
            if (node.type_id == 0 || node.confidence > 100 || node.coordinate.layer != decompiler_coordinate_layer_t::hir ||
                !same_entity(node.coordinate.entity, value.entity))
                result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_hir, "decompiler.hir.value"));
            if (node.id <= previous_value_id)
                result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_hir, "decompiler.hir.value_order"));
            previous_value_id = node.id;
            append(result, validate_source_coordinate(node.coordinate));
        }
    }
    for (const auto& coordinate : value.source_coordinates) {
        append(result, validate_source_coordinate(coordinate));
        if (coordinate.layer != decompiler_coordinate_layer_t::hir || !same_entity(coordinate.entity, value.entity))
            result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::source_map_rejected, "decompiler.hir.source_entity"));
    }
    for (const auto& unknown : value.unknowns) {
        if (!valid_unknown(unknown) || !same_entity(unknown.coordinate.entity, value.entity))
            result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_hir, "decompiler.hir.unknown"));
    }
    append_diagnostic_validation(result, value.diagnostics, decompiler_diagnostic_code_t::malformed_hir,
        "decompiler.hir.diagnostics", "decompiler.hir.diagnostic", "decompiler.hir.diagnostic_coordinate",
        &value.entity, decompiler_coordinate_layer_t::hir);
    return result;
}

decompiler_contract_validation_t validate_type_graph(const type_graph_t& value)
{
    decompiler_contract_validation_t result;
    if (value.schema_version != k_type_graph_schema_version || value.revision == 0 || value.nodes.empty())
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_type_graph, "decompiler.type_graph.header"));
    append(result, validate_decompiler_entity_key(value.entity));
    const bool ordered_nodes = strictly_increasing_ids(value.nodes, [](const decompiler_type_node_t& node) { return node.id; });
    if (!ordered_nodes)
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_type_graph, "decompiler.type_graph.node_order"));
    const auto has_type = [&value, ordered_nodes](std::uint64_t id) {
        if (!ordered_nodes)
            return false;
        const auto iterator = std::lower_bound(value.nodes.begin(), value.nodes.end(), id,
            [](const decompiler_type_node_t& node, std::uint64_t candidate) { return node.id < candidate; });
        return iterator != value.nodes.end() && iterator->id == id;
    };
    for (const auto& node : value.nodes) {
        if (node.canonical_name.empty() || node.display_name.empty() || node.confidence > 100 ||
            (node.byte_size && *node.byte_size == 0))
            result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_type_graph, "decompiler.type_graph.node"));
        for (const auto& coordinate : node.coordinates) {
            append(result, validate_source_coordinate(coordinate));
            if (!same_entity(coordinate.entity, value.entity))
                result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::source_map_rejected, "decompiler.type_graph.node_entity"));
        }
    }
    std::uint32_t previous_ordinal = 0;
    for (const auto& edge : value.edges) {
        if (edge.source_type_id == 0 || edge.target_type_id == 0 || edge.ordinal == 0 || edge.ordinal <= previous_ordinal ||
            edge.confidence > 100 || edge.stable_name.empty() || !has_type(edge.source_type_id) || !has_type(edge.target_type_id))
            result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_type_graph, "decompiler.type_graph.edge"));
        previous_ordinal = edge.ordinal;
    }
    for (const auto& unknown : value.unknowns) {
        if (!valid_unknown(unknown) || !same_entity(unknown.coordinate.entity, value.entity))
            result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_type_graph, "decompiler.type_graph.unknown"));
    }
    append_diagnostic_validation(result, value.diagnostics, decompiler_diagnostic_code_t::malformed_type_graph,
        "decompiler.type_graph.diagnostics", "decompiler.type_graph.diagnostic",
        "decompiler.type_graph.diagnostic_coordinate", &value.entity, std::nullopt);
    return result;
}

decompiler_contract_validation_t validate_typed_pseudocode_ast(const typed_pseudocode_ast_v2_t& value)
{
    decompiler_contract_validation_t result;
    if (value.schema_version != k_typed_pseudocode_ast_schema_version || value.hir_hash.empty() || value.type_graph_hash.empty() ||
        value.root_node_id == 0 || value.body_node_id == 0 || value.nodes.empty())
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_ast, "decompiler.ast.header"));
    append(result, validate_decompiler_entity_key(value.entity));
    const bool ordered_nodes = strictly_increasing_ids(value.nodes, [](const typed_pseudocode_ast_node_t& node) { return node.id; });
    if (!ordered_nodes)
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_ast, "decompiler.ast.node_order"));
    const typed_pseudocode_ast_node_t* root = nullptr;
    const typed_pseudocode_ast_node_t* body = nullptr;
    const auto has_node = [&value, ordered_nodes](std::uint64_t id) {
        if (!ordered_nodes)
            return false;
        const auto iterator = std::lower_bound(value.nodes.begin(), value.nodes.end(), id,
            [](const typed_pseudocode_ast_node_t& node, std::uint64_t candidate) { return node.id < candidate; });
        return iterator != value.nodes.end() && iterator->id == id;
    };
    for (const auto& node : value.nodes) {
        if (node.id == value.root_node_id)
            root = &node;
        if (node.id == value.body_node_id)
            body = &node;
        if (node.confidence > 100 || node.coordinate.layer != decompiler_coordinate_layer_t::typed_ast ||
            !same_entity(node.coordinate.entity, value.entity))
            result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_ast, "decompiler.ast.node"));
        bool duplicate_child = false;
        for (auto iterator = node.child_ids.begin(); iterator != node.child_ids.end() && !duplicate_child; ++iterator)
            duplicate_child = std::find(std::next(iterator), node.child_ids.end(), *iterator) != node.child_ids.end();
        if (std::any_of(node.child_ids.begin(), node.child_ids.end(), [&has_node](std::uint64_t id) { return !has_node(id); }) ||
            duplicate_child)
            result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_ast, "decompiler.ast.child"));
        append(result, validate_source_coordinate(node.coordinate));
    }
    if (!root || !body || root->kind != typed_pseudocode_ast_node_kind_t::function_definition ||
        body->kind != typed_pseudocode_ast_node_kind_t::compound_statement || body->child_ids.empty() ||
        std::find(root->child_ids.begin(), root->child_ids.end(), value.body_node_id) == root->child_ids.end())
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_ast, "decompiler.ast.nonempty_body"));
    for (const auto& coordinate : value.source_coordinates) {
        append(result, validate_source_coordinate(coordinate));
        if (coordinate.layer != decompiler_coordinate_layer_t::typed_ast || !same_entity(coordinate.entity, value.entity))
            result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::source_map_rejected, "decompiler.ast.source_entity"));
    }
    for (const auto& unknown : value.unknowns) {
        if (!valid_unknown(unknown) || !same_entity(unknown.coordinate.entity, value.entity))
            result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_ast, "decompiler.ast.unknown"));
    }
    append_diagnostic_validation(result, value.diagnostics, decompiler_diagnostic_code_t::malformed_ast,
        "decompiler.ast.diagnostics", "decompiler.ast.diagnostic", "decompiler.ast.diagnostic_coordinate",
        &value.entity, decompiler_coordinate_layer_t::typed_ast);
    return result;
}

decompiler_contract_validation_t validate_decompiler_document(const decompiler_document_t& value)
{
    decompiler_contract_validation_t result;
    if (value.schema_version != k_decompiler_document_schema_version || value.rendered_text.empty() ||
        value.ast_hash.empty() || value.type_graph_hash.empty() || !valid_renderer(value.renderer) || value.tokens.empty() ||
        value.source_maps.empty() || !same_entity(value.entity, value.ast.entity))
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_document, "decompiler.document.header"));
    append(result, validate_decompiler_entity_key(value.entity));
    const auto ast_validation = validate_typed_pseudocode_ast(value.ast);
    append(result, ast_validation);
    if (ast_validation.valid() && !value.ast_hash.empty() && value.ast_hash != stable_serialization_hash(value.ast))
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_document, "decompiler.document.ast_hash"));
    if (value.type_graph_hash != value.ast.type_graph_hash)
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_document, "decompiler.document.type_graph_hash"));
    std::uint32_t expected_begin = 0;
    const bool ordered_ast_nodes = strictly_increasing_ids(value.ast.nodes, [](const typed_pseudocode_ast_node_t& node) { return node.id; });
    const auto ast_node_exists = [&value, ordered_ast_nodes](std::uint64_t id) {
        if (!ordered_ast_nodes)
            return false;
        const auto iterator = std::lower_bound(value.ast.nodes.begin(), value.ast.nodes.end(), id,
            [](const typed_pseudocode_ast_node_t& node, std::uint64_t candidate) { return node.id < candidate; });
        return iterator != value.ast.nodes.end() && iterator->id == id;
    };
    for (const auto& token : value.tokens) {
        if (!valid_range(token.range) || token.range.begin != expected_begin || token.range.end > value.rendered_text.size() ||
            token.ast_node_id == 0 || !ast_node_exists(token.ast_node_id))
            result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_document, "decompiler.document.token"));
        expected_begin = token.range.end;
    }
    if (expected_begin != value.rendered_text.size())
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_document, "decompiler.document.token_coverage"));
    std::uint32_t previous_end = 0;
    for (const auto& map : value.source_maps) {
        if (!valid_range(map.document_range) || map.document_range.begin < previous_end ||
            map.document_range.end > value.rendered_text.size() || map.coordinates.empty())
            result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::source_map_rejected, "decompiler.document.source_map"));
        previous_end = map.document_range.end;
        for (const auto& coordinate : map.coordinates) {
            append(result, validate_source_coordinate(coordinate));
            if (coordinate.layer != decompiler_coordinate_layer_t::document || !coordinate.document_range ||
                coordinate.document_range->begin != map.document_range.begin ||
                coordinate.document_range->end != map.document_range.end || !same_entity(coordinate.entity, value.entity))
                result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::source_map_rejected, "decompiler.document.coordinate"));
        }
    }
    for (const auto& unknown : value.unknowns) {
        if (!valid_unknown(unknown) || !same_entity(unknown.coordinate.entity, value.entity))
            result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::malformed_document, "decompiler.document.unknown"));
    }
    append_diagnostic_validation(result, value.diagnostics, decompiler_diagnostic_code_t::malformed_document,
        "decompiler.document.diagnostics", "decompiler.document.diagnostic",
        "decompiler.document.diagnostic_coordinate", &value.entity, decompiler_coordinate_layer_t::document);
    return result;
}

decompiler_contract_validation_t validate_decompiler_profile(const decompiler_profile_budget_t& value)
{
    decompiler_contract_validation_t result;
    if (value.schema_version != 1 || value.max_wall_clock_ms == 0 || value.max_cpu_ms == 0 ||
        value.max_cpu_ms > k_decompiler_profile_max_cpu_ms || value.max_memory_bytes == 0 ||
        value.max_memory_bytes > k_decompiler_profile_max_memory_bytes || value.max_provider_ir_nodes == 0 || value.max_hir_nodes == 0 ||
        value.max_ast_nodes == 0)
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::invalid_contract, "decompiler.profile.budget"));
    if (value.profile != decompiler_profile_id_t::fast && value.profile != decompiler_profile_id_t::balanced &&
        value.profile != decompiler_profile_id_t::thorough) {
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::invalid_contract, "decompiler.profile.id"));
    } else if (value.profile == decompiler_profile_id_t::thorough) {
        if (!value.semantic_proofs_enabled || value.max_semantic_queries == 0)
            result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::invalid_contract, "decompiler.profile.thorough"));
    } else if (value.semantic_proofs_enabled || value.max_semantic_queries != 0) {
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::invalid_contract, "decompiler.profile.semantic_scope"));
    }
    return result;
}

decompiler_contract_validation_t validate_decompiler_pipeline_cache_key(const decompiler_pipeline_cache_key_t& value)
{
    decompiler_contract_validation_t result;
    if (value.schema_version != k_decompiler_cache_key_schema_version ||
        (value.stage != decompiler_cache_stage_t::provider_ir &&
            value.stage != decompiler_cache_stage_t::normalized_hir_ast &&
            value.stage != decompiler_cache_stage_t::rendered_document) ||
        value.workspace_id.empty() ||
        value.workspace_generation == 0 || !valid_provider(value.provider) || !valid_language(value.language) ||
        !language_matches_entity(value.language, value.entity) ||
        value.worker_protocol_version != k_decompiler_worker_protocol_version || value.worker_protocol_hash.empty() ||
        value.loader_layout_hash.empty() || value.function_bytes_hash.empty() ||
        value.provider_ir_schema_version != k_provider_ir_schema_version ||
        value.hir_schema_version != k_hir_schema_version || value.type_graph_schema_version != k_type_graph_schema_version ||
        value.ast_schema_version != k_typed_pseudocode_ast_schema_version ||
        value.document_schema_version != k_decompiler_document_schema_version || !valid_renderer(value.renderer) ||
        value.dependencies.empty())
        result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::cache_key_rejected, "decompiler.cache.header"));
    append(result, validate_decompiler_entity_key(value.entity));
    append(result, validate_decompiler_profile(value.profile));
    address_t previous_end{};
    bool have_previous = false;
    for (const auto& chunk : value.chunk_fingerprints) {
        if (!valid_range({chunk.begin, chunk.end}) || chunk.bytes_hash.empty() ||
            (have_previous && !(previous_end < chunk.begin)))
            result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::cache_key_rejected, "decompiler.cache.chunk"));
        previous_end = chunk.end;
        have_previous = true;
    }
    std::string previous_name;
    for (const auto& dependency : value.dependencies) {
        if (dependency.name.empty() || dependency.version.empty() || dependency.content_hash.empty() ||
            (!previous_name.empty() && dependency.name <= previous_name))
            result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::cache_key_rejected, "decompiler.cache.dependency"));
        previous_name = dependency.name;
    }
    return result;
}

decompiler_contract_validation_t validate_decompiler_worker_message(const decompiler_worker_message_t& value)
{
    decompiler_contract_validation_t result;
    std::visit([&result](const auto& message) {
        const auto& envelope = message.envelope;
        if (envelope.protocol_version != k_decompiler_worker_protocol_version || envelope.session_nonce_hash.empty() ||
            envelope.sequence == 0)
            result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::worker_protocol_failure, "decompiler.worker.envelope"));
        using message_t = std::decay_t<decltype(message)>;
        if constexpr (std::is_same_v<message_t, decompiler_worker_hello_t>) {
            if (envelope.kind != decompiler_worker_message_kind_t::hello || !valid_provider(message.provider) || message.manifest_hash.empty())
                result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::worker_protocol_failure, "decompiler.worker.hello"));
        } else if constexpr (std::is_same_v<message_t, decompiler_worker_job_request_t>) {
            if (envelope.kind != decompiler_worker_message_kind_t::job_request || message.job_id == 0 || message.snapshot_hash.empty())
                result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::worker_protocol_failure, "decompiler.worker.request"));
            append(result, validate_decompiler_pipeline_cache_key(message.cache_key));
            append(result, validate_decompiler_profile(message.profile));
            if (message.cache_key.profile.profile != message.profile.profile ||
                message.cache_key.profile.schema_version != message.profile.schema_version ||
                message.cache_key.profile.max_wall_clock_ms != message.profile.max_wall_clock_ms ||
                message.cache_key.profile.max_cpu_ms != message.profile.max_cpu_ms ||
                message.cache_key.profile.max_memory_bytes != message.profile.max_memory_bytes ||
                message.cache_key.profile.max_provider_ir_nodes != message.profile.max_provider_ir_nodes ||
                message.cache_key.profile.max_hir_nodes != message.profile.max_hir_nodes ||
                message.cache_key.profile.max_ast_nodes != message.profile.max_ast_nodes ||
                message.cache_key.profile.max_semantic_queries != message.profile.max_semantic_queries ||
                message.cache_key.profile.semantic_proofs_enabled != message.profile.semantic_proofs_enabled)
                result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::worker_protocol_failure, "decompiler.worker.profile_binding"));
            if (message.request_printc_evidence &&
                message.cache_key.provider.provider != decompiler_provider_id_t::ghidra_native)
                result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::worker_protocol_failure, "decompiler.worker.printc_request"));
        } else if constexpr (std::is_same_v<message_t, decompiler_worker_cancel_request_t>) {
            if (envelope.kind != decompiler_worker_message_kind_t::cancel_request || message.job_id == 0 || message.stable_reason.empty())
                result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::worker_protocol_failure, "decompiler.worker.cancel"));
        } else if constexpr (std::is_same_v<message_t, decompiler_worker_document_message_t>) {
            if (envelope.kind != decompiler_worker_message_kind_t::document || message.job_id == 0 ||
                message.provider_artifacts.empty() ||
                message.provider_artifacts.size() > k_decompiler_worker_provider_artifacts_max_bytes ||
                message.provider_artifacts_hash.empty() ||
                stable_serialization_hash(message.provider_artifacts) != message.provider_artifacts_hash)
                result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::worker_protocol_failure, "decompiler.worker.document"));
            if ((message.printc_evidence.has_value() &&
                    (message.printc_evidence->empty() ||
                     message.printc_evidence->size() > k_decompiler_worker_printc_evidence_max_bytes ||
                     message.printc_evidence_hash.empty() ||
                     stable_serialization_hash(*message.printc_evidence) != message.printc_evidence_hash)) ||
                (!message.printc_evidence.has_value() && !message.printc_evidence_hash.empty()))
                result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::worker_protocol_failure, "decompiler.worker.printc_evidence"));
            append(result, validate_decompiler_document(message.document));
        } else if constexpr (std::is_same_v<message_t, decompiler_worker_failure_message_t>) {
            if (envelope.kind != decompiler_worker_message_kind_t::failure || message.job_id == 0 || message.diagnostics.empty())
                result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::worker_protocol_failure, "decompiler.worker.failure"));
            append_diagnostic_validation(result, message.diagnostics, decompiler_diagnostic_code_t::worker_protocol_failure,
                "decompiler.worker.failure_diagnostics", "decompiler.worker.failure_diagnostic",
                "decompiler.worker.failure_coordinate", nullptr, std::nullopt);
            for (const auto& diagnostic : message.diagnostics) {
                if (diagnostic.severity != decompiler_diagnostic_severity_t::error)
                    result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::worker_protocol_failure, "decompiler.worker.failure_diagnostic"));
            }
        } else {
            if (envelope.kind != decompiler_worker_message_kind_t::heartbeat)
                result.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::worker_protocol_failure, "decompiler.worker.heartbeat"));
        }
    }, value);
    return result;
}

std::string serialize_decompiler_entity_key(const decompiler_entity_key_t& value)
{
    require_valid(validate_decompiler_entity_key(value));
    canonical_writer_t writer;
    writer.u32(k_magic_entity);
    write_entity(writer, value);
    return writer.take();
}

std::string serialize_source_coordinate(const source_coordinate_t& value)
{
    require_valid(validate_source_coordinate(value));
    canonical_writer_t writer;
    writer.u32(k_magic_coordinate);
    write_coordinate(writer, value);
    return writer.take();
}

std::string serialize_provider_ir(const provider_ir_t& value)
{
    require_valid(validate_provider_ir(value));
    canonical_writer_t writer;
    writer.u32(k_magic_provider_ir);
    writer.u32(value.schema_version);
    write_provider(writer, value.provider);
    write_language(writer, value.language);
    write_entity(writer, value.entity);
    writer.u64(value.entry_block_id);
    write_vector(writer, value.blocks, write_provider_block);
    write_vector(writer, value.source_coordinates, write_coordinate);
    write_vector(writer, value.unknowns, write_unknown);
    write_vector(writer, value.diagnostics, write_diagnostic);
    return writer.take();
}

std::string serialize_hir_function(const hir_function_t& value)
{
    require_valid(validate_hir_function(value));
    canonical_writer_t writer;
    writer.u32(k_magic_hir);
    writer.u32(value.schema_version);
    write_entity(writer, value.entity);
    writer.digest(value.provider_ir_hash);
    writer.u64(value.type_graph_revision);
    writer.u64(value.return_type_id);
    write_vector(writer, value.parameters, write_hir_variable);
    write_vector(writer, value.locals, write_hir_variable);
    write_vector(writer, value.blocks, write_hir_block);
    write_vector(writer, value.source_coordinates, write_coordinate);
    write_vector(writer, value.unknowns, write_unknown);
    write_vector(writer, value.diagnostics, write_diagnostic);
    return writer.take();
}

std::string serialize_type_graph(const type_graph_t& value)
{
    require_valid(validate_type_graph(value));
    canonical_writer_t writer;
    writer.u32(k_magic_type_graph);
    writer.u32(value.schema_version);
    write_entity(writer, value.entity);
    writer.u64(value.revision);
    write_vector(writer, value.nodes, write_type_node);
    write_vector(writer, value.edges, write_type_edge);
    write_vector(writer, value.unknowns, write_unknown);
    write_vector(writer, value.diagnostics, write_diagnostic);
    return writer.take();
}

std::string serialize_typed_pseudocode_ast(const typed_pseudocode_ast_v2_t& value)
{
    require_valid(validate_typed_pseudocode_ast(value));
    canonical_writer_t writer;
    writer.u32(k_magic_ast);
    writer.u32(value.schema_version);
    write_entity(writer, value.entity);
    writer.digest(value.hir_hash);
    writer.digest(value.type_graph_hash);
    writer.u64(value.root_node_id);
    writer.u64(value.body_node_id);
    write_vector(writer, value.nodes, write_ast_node);
    write_vector(writer, value.source_coordinates, write_coordinate);
    write_vector(writer, value.unknowns, write_unknown);
    write_vector(writer, value.diagnostics, write_diagnostic);
    return writer.take();
}

std::string serialize_decompiler_document(const decompiler_document_t& value)
{
    require_valid(validate_decompiler_document(value));
    canonical_writer_t writer;
    writer.u32(k_magic_document);
    writer.u32(value.schema_version);
    write_entity(writer, value.entity);
    writer.string(serialize_typed_pseudocode_ast(value.ast));
    writer.digest(value.ast_hash);
    writer.digest(value.type_graph_hash);
    write_enum(writer, value.profile);
    write_renderer(writer, value.renderer);
    writer.string(value.rendered_text);
    write_vector(writer, value.tokens, write_document_token);
    write_vector(writer, value.source_maps, write_document_source_map);
    write_vector(writer, value.unknowns, write_unknown);
    write_vector(writer, value.diagnostics, write_diagnostic);
    return writer.take();
}

std::string serialize_decompiler_diagnostic(const decompiler_diagnostic_t& value)
{
    if (!valid_diagnostic(value) || (value.coordinate && !validate_source_coordinate(*value.coordinate).valid()))
        throw std::invalid_argument("invalid decompiler diagnostic");
    canonical_writer_t writer;
    writer.u32(k_magic_diagnostic);
    write_diagnostic(writer, value);
    return writer.take();
}

std::string serialize_decompiler_pipeline_cache_key(const decompiler_pipeline_cache_key_t& value)
{
    require_valid(validate_decompiler_pipeline_cache_key(value));
    canonical_writer_t writer;
    writer.u32(k_magic_cache);
    write_cache_key(writer, value);
    return writer.take();
}

std::string serialize_decompiler_worker_message(const decompiler_worker_message_t& value)
{
    require_valid(validate_decompiler_worker_message(value));
    canonical_writer_t writer;
    writer.u32(k_magic_worker);
    std::visit([&writer](const auto& message) {
        write_envelope(writer, message.envelope);
        using message_t = std::decay_t<decltype(message)>;
        if constexpr (std::is_same_v<message_t, decompiler_worker_hello_t>) {
            write_provider(writer, message.provider);
            writer.digest(message.manifest_hash);
        } else if constexpr (std::is_same_v<message_t, decompiler_worker_job_request_t>) {
            writer.u64(message.job_id);
            write_cache_key(writer, message.cache_key);
            write_profile(writer, message.profile);
            writer.digest(message.snapshot_hash);
            writer.u8(message.request_printc_evidence ? 1U : 0U);
        } else if constexpr (std::is_same_v<message_t, decompiler_worker_cancel_request_t>) {
            writer.u64(message.job_id);
            writer.string(message.stable_reason);
        } else if constexpr (std::is_same_v<message_t, decompiler_worker_document_message_t>) {
            writer.u64(message.job_id);
            writer.string(message.provider_artifacts);
            writer.digest(message.provider_artifacts_hash);
            writer.u8(message.printc_evidence.has_value() ? 1U : 0U);
            if (message.printc_evidence) {
                writer.string(*message.printc_evidence);
                writer.digest(message.printc_evidence_hash);
            }
            writer.string(serialize_decompiler_document(message.document));
        } else if constexpr (std::is_same_v<message_t, decompiler_worker_failure_message_t>) {
            writer.u64(message.job_id);
            write_vector(writer, message.diagnostics, write_diagnostic);
        } else {
            writer.u64(message.active_job_id);
        }
    }, value);
    return writer.take();
}

decompiler_contract_decode_result_t<decompiler_entity_key_t> deserialize_decompiler_entity_key(const std::string& value)
{
    return decode_root<decompiler_entity_key_t>(value, k_magic_entity, read_entity, validate_decompiler_entity_key);
}

decompiler_contract_decode_result_t<source_coordinate_t> deserialize_source_coordinate(const std::string& value)
{
    return decode_root<source_coordinate_t>(value, k_magic_coordinate, read_coordinate, validate_source_coordinate);
}

decompiler_contract_decode_result_t<provider_ir_t> deserialize_provider_ir(const std::string& value)
{
    return decode_root<provider_ir_t>(value, k_magic_provider_ir, [](canonical_reader_t& reader, provider_ir_t& decoded) {
        return reader.u32(decoded.schema_version) && read_provider(reader, decoded.provider) &&
            read_language(reader, decoded.language) && read_entity(reader, decoded.entity) &&
            reader.u64(decoded.entry_block_id) && read_vector(reader, decoded.blocks, read_provider_block) &&
            read_vector(reader, decoded.source_coordinates, read_coordinate) &&
            read_vector(reader, decoded.unknowns, read_unknown) && read_vector(reader, decoded.diagnostics, read_diagnostic);
    }, validate_provider_ir);
}

decompiler_contract_decode_result_t<hir_function_t> deserialize_hir_function(const std::string& value)
{
    return decode_root<hir_function_t>(value, k_magic_hir, [](canonical_reader_t& reader, hir_function_t& decoded) {
        return reader.u32(decoded.schema_version) && read_entity(reader, decoded.entity) &&
            reader.digest(decoded.provider_ir_hash) && reader.u64(decoded.type_graph_revision) &&
            reader.u64(decoded.return_type_id) && read_vector(reader, decoded.parameters, read_hir_variable) &&
            read_vector(reader, decoded.locals, read_hir_variable) && read_vector(reader, decoded.blocks, read_hir_block) &&
            read_vector(reader, decoded.source_coordinates, read_coordinate) &&
            read_vector(reader, decoded.unknowns, read_unknown) && read_vector(reader, decoded.diagnostics, read_diagnostic);
    }, validate_hir_function);
}

decompiler_contract_decode_result_t<type_graph_t> deserialize_type_graph(const std::string& value)
{
    return decode_root<type_graph_t>(value, k_magic_type_graph, [](canonical_reader_t& reader, type_graph_t& decoded) {
        return reader.u32(decoded.schema_version) && read_entity(reader, decoded.entity) && reader.u64(decoded.revision) &&
            read_vector(reader, decoded.nodes, read_type_node) && read_vector(reader, decoded.edges, read_type_edge) &&
            read_vector(reader, decoded.unknowns, read_unknown) && read_vector(reader, decoded.diagnostics, read_diagnostic);
    }, validate_type_graph);
}

decompiler_contract_decode_result_t<typed_pseudocode_ast_v2_t> deserialize_typed_pseudocode_ast(const std::string& value)
{
    return decode_root<typed_pseudocode_ast_v2_t>(value, k_magic_ast, [](canonical_reader_t& reader, typed_pseudocode_ast_v2_t& decoded) {
        return reader.u32(decoded.schema_version) && read_entity(reader, decoded.entity) && reader.digest(decoded.hir_hash) &&
            reader.digest(decoded.type_graph_hash) && reader.u64(decoded.root_node_id) && reader.u64(decoded.body_node_id) &&
            read_vector(reader, decoded.nodes, read_ast_node) && read_vector(reader, decoded.source_coordinates, read_coordinate) &&
            read_vector(reader, decoded.unknowns, read_unknown) && read_vector(reader, decoded.diagnostics, read_diagnostic);
    }, validate_typed_pseudocode_ast);
}

decompiler_contract_decode_result_t<decompiler_document_t> deserialize_decompiler_document(const std::string& value)
{
    return decode_root<decompiler_document_t>(value, k_magic_document, [](canonical_reader_t& reader, decompiler_document_t& decoded) {
        std::string ast_bytes;
        if (!reader.u32(decoded.schema_version) || !read_entity(reader, decoded.entity) || !reader.string(ast_bytes))
            return false;
        auto ast = deserialize_typed_pseudocode_ast(ast_bytes);
        if (!ast.valid())
            return false;
        decoded.ast = std::move(*ast.value);
        return reader.digest(decoded.ast_hash) && reader.digest(decoded.type_graph_hash) && read_enum(reader, decoded.profile) &&
            read_renderer(reader, decoded.renderer) && reader.string(decoded.rendered_text) &&
            read_vector(reader, decoded.tokens, read_document_token) &&
            read_vector(reader, decoded.source_maps, read_document_source_map) &&
            read_vector(reader, decoded.unknowns, read_unknown) && read_vector(reader, decoded.diagnostics, read_diagnostic);
    }, validate_decompiler_document);
}

decompiler_contract_decode_result_t<decompiler_diagnostic_t> deserialize_decompiler_diagnostic(const std::string& value)
{
    return decode_root<decompiler_diagnostic_t>(value, k_magic_diagnostic, read_diagnostic, [](const decompiler_diagnostic_t& decoded) {
        decompiler_contract_validation_t validation;
        if (!valid_diagnostic(decoded) || (decoded.coordinate && !validate_source_coordinate(*decoded.coordinate).valid()))
            validation.diagnostics.push_back(contract_error(decompiler_diagnostic_code_t::invalid_contract, "decompiler.diagnostic"));
        return validation;
    });
}

decompiler_contract_decode_result_t<decompiler_pipeline_cache_key_t> deserialize_decompiler_pipeline_cache_key(const std::string& value)
{
    return decode_root<decompiler_pipeline_cache_key_t>(value, k_magic_cache, read_cache_key, validate_decompiler_pipeline_cache_key);
}

decompiler_contract_decode_result_t<decompiler_worker_message_t> deserialize_decompiler_worker_message(const std::string& value)
{
    return decode_root<decompiler_worker_message_t>(value, k_magic_worker, [](canonical_reader_t& reader, decompiler_worker_message_t& decoded) {
        decompiler_worker_envelope_t envelope;
        if (!read_envelope(reader, envelope))
            return false;
        switch (envelope.kind) {
        case decompiler_worker_message_kind_t::hello: {
            decompiler_worker_hello_t message;
            message.envelope = envelope;
            if (!read_provider(reader, message.provider) || !reader.digest(message.manifest_hash))
                return false;
            decoded = std::move(message);
            return true;
        }
        case decompiler_worker_message_kind_t::job_request: {
            decompiler_worker_job_request_t message;
            std::uint8_t request_printc_evidence = 0;
            message.envelope = envelope;
            if (!reader.u64(message.job_id) || !read_cache_key(reader, message.cache_key) ||
                !read_profile(reader, message.profile) || !reader.digest(message.snapshot_hash) ||
                !reader.u8(request_printc_evidence) || request_printc_evidence > 1U)
                return false;
            message.request_printc_evidence = request_printc_evidence != 0;
            decoded = std::move(message);
            return true;
        }
        case decompiler_worker_message_kind_t::cancel_request: {
            decompiler_worker_cancel_request_t message;
            message.envelope = envelope;
            if (!reader.u64(message.job_id) || !reader.string(message.stable_reason))
                return false;
            decoded = std::move(message);
            return true;
        }
        case decompiler_worker_message_kind_t::document: {
            decompiler_worker_document_message_t message;
            std::string document_bytes;
            std::uint8_t has_printc_evidence = 0;
            message.envelope = envelope;
            if (!reader.u64(message.job_id) || !reader.string(message.provider_artifacts) ||
                !reader.digest(message.provider_artifacts_hash) || !reader.u8(has_printc_evidence) ||
                has_printc_evidence > 1U)
                return false;
            if (has_printc_evidence != 0) {
                std::string evidence;
                if (!reader.string(evidence) || !reader.digest(message.printc_evidence_hash))
                    return false;
                message.printc_evidence = std::move(evidence);
            }
            if (!reader.string(document_bytes))
                return false;
            auto document = deserialize_decompiler_document(document_bytes);
            if (!document.valid())
                return false;
            message.document = std::move(*document.value);
            decoded = std::move(message);
            return true;
        }
        case decompiler_worker_message_kind_t::failure: {
            decompiler_worker_failure_message_t message;
            message.envelope = envelope;
            if (!reader.u64(message.job_id) || !read_vector(reader, message.diagnostics, read_diagnostic))
                return false;
            decoded = std::move(message);
            return true;
        }
        case decompiler_worker_message_kind_t::heartbeat: {
            decompiler_worker_heartbeat_t message;
            message.envelope = envelope;
            if (!reader.u64(message.active_job_id))
                return false;
            decoded = std::move(message);
            return true;
        }
        }
        return false;
    }, validate_decompiler_worker_message);
}

sha256_digest_t stable_serialization_hash(const std::string& bytes)
{
    sha256_t hash;
    hash.update(reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size());
    return hash.finish();
}

sha256_digest_t stable_serialization_hash(const decompiler_entity_key_t& value) { return stable_serialization_hash(serialize_decompiler_entity_key(value)); }
sha256_digest_t stable_serialization_hash(const source_coordinate_t& value) { return stable_serialization_hash(serialize_source_coordinate(value)); }
sha256_digest_t stable_serialization_hash(const provider_ir_t& value) { return stable_serialization_hash(serialize_provider_ir(value)); }
sha256_digest_t stable_serialization_hash(const hir_function_t& value) { return stable_serialization_hash(serialize_hir_function(value)); }
sha256_digest_t stable_serialization_hash(const type_graph_t& value) { return stable_serialization_hash(serialize_type_graph(value)); }
sha256_digest_t stable_serialization_hash(const typed_pseudocode_ast_v2_t& value) { return stable_serialization_hash(serialize_typed_pseudocode_ast(value)); }
sha256_digest_t stable_serialization_hash(const decompiler_document_t& value) { return stable_serialization_hash(serialize_decompiler_document(value)); }
sha256_digest_t stable_serialization_hash(const decompiler_diagnostic_t& value) { return stable_serialization_hash(serialize_decompiler_diagnostic(value)); }
sha256_digest_t stable_serialization_hash(const decompiler_pipeline_cache_key_t& value) { return stable_serialization_hash(serialize_decompiler_pipeline_cache_key(value)); }
sha256_digest_t stable_serialization_hash(const decompiler_worker_message_t& value) { return stable_serialization_hash(serialize_decompiler_worker_message(value)); }

}
