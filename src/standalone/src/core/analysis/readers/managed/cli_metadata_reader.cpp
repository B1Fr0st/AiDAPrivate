#include "cli_metadata_reader.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <string_view>
#include <unordered_set>

namespace aida::analysis::readers::managed {
namespace {

workspace_error_t cli_error(workspace_error_code_t code, std::string message,
                            std::string phase, std::optional<std::uint64_t> offset = {},
                            std::optional<std::uint64_t> size = {}) {
    auto error = make_workspace_error(code, std::move(message), std::move(phase));
    error.offset = offset;
    error.size = size;
    return error;
}

workspace_error_t cli_stop_error(
    const cancellation_token_t& cancel,
    std::string message,
    std::string phase) {
    auto error = cli_error(
        cancel.deadline_exceeded()
            ? workspace_error_code_t::deadline_exceeded
            : workspace_error_code_t::cancelled,
        std::move(message), std::move(phase));
    error.deadline = cancel.deadline_exceeded();
    error.cancellation = !error.deadline;
    return error;
}

bool span_within(std::uint64_t offset, std::uint64_t size, std::uint64_t limit) noexcept {
    return offset <= limit && size <= limit - offset;
}

std::uint16_t read_u16_le(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>(p[0]) | (static_cast<std::uint16_t>(p[1]) << 8);
}

std::uint32_t read_u32_le(const std::uint8_t* p) noexcept {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint64_t read_u64_le(const std::uint8_t* p) noexcept {
    return static_cast<std::uint64_t>(read_u32_le(p)) |
           (static_cast<std::uint64_t>(read_u32_le(p + 4)) << 32);
}

struct cli_byte_reader_t {
    const std::uint8_t* data = nullptr;
    std::uint64_t size = 0;
    std::uint64_t offset = 0;

    bool require(std::uint64_t length, std::string_view phase) {
        if (!span_within(offset, length, size)) {
            error_ = cli_error(workspace_error_code_t::out_of_range,
                               "CLI metadata structure exceeds input bounds",
                               std::string(phase), offset, length);
            return false;
        }
        return true;
    }

    bool u8(std::uint8_t& value, std::string_view phase) {
        if (!require(1, phase)) return false;
        value = data[offset++];
        return true;
    }

    bool u16(std::uint16_t& value, std::string_view phase) {
        if (!require(2, phase)) return false;
        value = read_u16_le(data + offset);
        offset += 2;
        return true;
    }

    bool u32(std::uint32_t& value, std::string_view phase) {
        if (!require(4, phase)) return false;
        value = read_u32_le(data + offset);
        offset += 4;
        return true;
    }

    bool u64(std::uint64_t& value, std::string_view phase) {
        if (!require(8, phase)) return false;
        value = read_u64_le(data + offset);
        offset += 8;
        return true;
    }

    bool bytes(std::vector<std::uint8_t>& value, std::uint64_t length, std::string_view phase) {
        if (!require(length, phase)) return false;
        value.assign(data + offset, data + offset + static_cast<std::size_t>(length));
        offset += length;
        return true;
    }

    bool skip(std::uint64_t length, std::string_view phase) {
        if (!require(length, phase)) return false;
        offset += length;
        return true;
    }

    workspace_error_t error_;
};

struct cli_stream_info_t {
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    bool found = false;
};

struct cli_heap_sizes_t {
    bool large_strings = false;
    bool large_guid = false;
    bool large_blob = false;
};

std::uint32_t string_index_size(const cli_heap_sizes_t& heaps) noexcept {
    return heaps.large_strings ? 4 : 2;
}

std::uint32_t guid_index_size(const cli_heap_sizes_t& heaps) noexcept {
    return heaps.large_guid ? 4 : 2;
}

std::uint32_t blob_index_size(const cli_heap_sizes_t& heaps) noexcept {
    return heaps.large_blob ? 4 : 2;
}

struct cli_coded_index_info_t {
    std::uint8_t tag_bits = 0;
    std::vector<std::uint8_t> table_ids;
};

cli_coded_index_info_t coded_index_type_def_or_ref() {
    return {2, {static_cast<std::uint8_t>(cli_table_id_t::type_def),
                static_cast<std::uint8_t>(cli_table_id_t::type_ref),
                0x1B}};
}

cli_coded_index_info_t coded_index_has_custom_attribute() {
    return {5, {static_cast<std::uint8_t>(cli_table_id_t::method_def),
                static_cast<std::uint8_t>(cli_table_id_t::field),
                0x01, static_cast<std::uint8_t>(cli_table_id_t::type_ref),
                static_cast<std::uint8_t>(cli_table_id_t::type_def),
                0x06, 0x08, 0x09, 0x0A, 0x00, 0x0E,
                static_cast<std::uint8_t>(cli_table_id_t::assembly),
                static_cast<std::uint8_t>(cli_table_id_t::assembly_ref),
                0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
                0x0C, 0x0D, 0x11, 0x1C, 0x0B}};
}

cli_coded_index_info_t coded_index_member_ref_parent() {
    return {3, {static_cast<std::uint8_t>(cli_table_id_t::type_def),
                static_cast<std::uint8_t>(cli_table_id_t::type_ref),
                0x00, static_cast<std::uint8_t>(cli_table_id_t::method_def),
                0x1B}};
}

cli_coded_index_info_t coded_index_resolution_scope() {
    return {2, {0x00, 0x1A, static_cast<std::uint8_t>(cli_table_id_t::assembly_ref),
                static_cast<std::uint8_t>(cli_table_id_t::type_ref)}};
}

cli_coded_index_info_t coded_index_implementation() {
    return {2, {0x16, static_cast<std::uint8_t>(cli_table_id_t::assembly_ref),
                0x17}};
}

cli_coded_index_info_t coded_index_type_or_method_def() {
    return {1, {static_cast<std::uint8_t>(cli_table_id_t::type_def),
                static_cast<std::uint8_t>(cli_table_id_t::method_def)}};
}

cli_coded_index_info_t coded_index_method_def_or_ref() {
    return {1, {static_cast<std::uint8_t>(cli_table_id_t::method_def),
                static_cast<std::uint8_t>(cli_table_id_t::member_ref)}};
}

cli_coded_index_info_t coded_index_custom_attribute_type() {
    return {3, {0, 0, static_cast<std::uint8_t>(cli_table_id_t::method_def),
                static_cast<std::uint8_t>(cli_table_id_t::member_ref), 0}};
}

cli_coded_index_info_t coded_index_has_semantics() {
    return {1, {0x14, 0x17}};
}

std::uint32_t coded_index_size(const cli_coded_index_info_t& info,
                                const cli_table_row_counts_t& counts) noexcept {
    std::uint32_t max_rows = 0;
    for (const auto table_id : info.table_ids) {
        if (table_id < cli_max_tables) {
            const auto rows = counts.counts[table_id];
            if (rows > max_rows)
                max_rows = rows;
        }
    }
    const std::uint32_t tag_limit = 1u << info.tag_bits;
    if (max_rows > (0xFFFFu >> (info.tag_bits)) || max_rows >= tag_limit)
        return 4;
    return 2;
}

std::uint32_t simple_index_size(std::uint32_t table_rows) noexcept {
    return table_rows > 0xFFFFu ? 4 : 2;
}

bool decode_coded_index(std::uint32_t raw, const cli_coded_index_info_t& info,
                         std::uint8_t& tag, std::uint32_t& index) {
    const std::uint32_t tag_mask = (1u << info.tag_bits) - 1u;
    tag = static_cast<std::uint8_t>(raw & tag_mask);
    index = raw >> info.tag_bits;
    if (tag >= info.table_ids.size())
        return false;
    return true;
}

std::uint32_t table_row_size(std::uint8_t table_id, const cli_heap_sizes_t& heaps,
                              const cli_table_row_counts_t& counts) noexcept {
    switch (static_cast<cli_table_id_t>(table_id)) {
        case cli_table_id_t::module:
            return 2 + string_index_size(heaps) + guid_index_size(heaps) * 2;
        case cli_table_id_t::type_ref:
            return coded_index_size(coded_index_resolution_scope(), counts) +
                   string_index_size(heaps) * 2;
        case cli_table_id_t::type_def:
            return 4 + string_index_size(heaps) * 2 +
                   coded_index_size(coded_index_type_def_or_ref(), counts) +
                   simple_index_size(counts.counts[static_cast<std::uint8_t>(cli_table_id_t::field)]) +
                   simple_index_size(counts.counts[static_cast<std::uint8_t>(cli_table_id_t::method_def)]);
        case cli_table_id_t::field:
            return 2 + string_index_size(heaps) + blob_index_size(heaps);
        case cli_table_id_t::method_def:
            return 4 + 2 + 2 + string_index_size(heaps) + blob_index_size(heaps) +
                   simple_index_size(counts.counts[static_cast<std::uint8_t>(cli_table_id_t::param)]);
        case cli_table_id_t::param:
            return 2 + 2 + string_index_size(heaps);
        case cli_table_id_t::interface_impl:
            return simple_index_size(counts.counts[static_cast<std::uint8_t>(cli_table_id_t::type_def)]) +
                   coded_index_size(coded_index_type_def_or_ref(), counts);
        case cli_table_id_t::member_ref:
            return coded_index_size(coded_index_member_ref_parent(), counts) +
                   string_index_size(heaps) + blob_index_size(heaps);
        case cli_table_id_t::constant:
            return 2 + 2 + coded_index_size({2, {static_cast<std::uint8_t>(cli_table_id_t::field),
                                                   static_cast<std::uint8_t>(cli_table_id_t::param),
                                                   0x17}}, counts) + blob_index_size(heaps);
        case cli_table_id_t::custom_attribute:
            return coded_index_size(coded_index_has_custom_attribute(), counts) +
                   coded_index_size(coded_index_custom_attribute_type(), counts) +
                   blob_index_size(heaps);
        case cli_table_id_t::field_marshal:
            return coded_index_size({1, {static_cast<std::uint8_t>(cli_table_id_t::field),
                                          static_cast<std::uint8_t>(cli_table_id_t::param)}}, counts) +
                   blob_index_size(heaps);
        case cli_table_id_t::decl_security:
            return 2 + coded_index_size({2, {static_cast<std::uint8_t>(cli_table_id_t::type_def),
                                              static_cast<std::uint8_t>(cli_table_id_t::method_def),
                                              static_cast<std::uint8_t>(cli_table_id_t::assembly)}}, counts) +
                   blob_index_size(heaps);
        case cli_table_id_t::class_layout:
            return 2 + 4 + simple_index_size(counts.counts[static_cast<std::uint8_t>(cli_table_id_t::type_def)]);
        case cli_table_id_t::field_layout:
            return 4 + simple_index_size(counts.counts[static_cast<std::uint8_t>(cli_table_id_t::field)]);
        case cli_table_id_t::semantics:
            return 2 + simple_index_size(counts.counts[0x14]) + coded_index_size(coded_index_has_semantics(), counts);
        case cli_table_id_t::impl_map:
            return 2 + coded_index_size({1, {static_cast<std::uint8_t>(cli_table_id_t::field),
                                              static_cast<std::uint8_t>(cli_table_id_t::method_def)}}, counts) +
                   string_index_size(heaps) + simple_index_size(counts.counts[static_cast<std::uint8_t>(cli_table_id_t::assembly_ref)]);
        case cli_table_id_t::field_rva:
            return 4 + simple_index_size(counts.counts[static_cast<std::uint8_t>(cli_table_id_t::field)]);
        case cli_table_id_t::assembly:
            return 4 + 2 + 2 + 2 + 2 + 4 + blob_index_size(heaps) + string_index_size(heaps) * 2;
        case cli_table_id_t::assembly_ref:
            return 2 + 2 + 2 + 2 + 4 + blob_index_size(heaps) + string_index_size(heaps) * 2 + blob_index_size(heaps);
        case cli_table_id_t::file:
            return 4 + string_index_size(heaps) + blob_index_size(heaps);
        case cli_table_id_t::exported_type:
            return 4 + string_index_size(heaps) * 2 +
                   coded_index_size(coded_index_implementation(), counts) +
                   string_index_size(heaps) + 4;
        case cli_table_id_t::manifest_resource:
            return 4 + 4 + string_index_size(heaps) +
                   coded_index_size(coded_index_implementation(), counts);
        case cli_table_id_t::nested_class:
            return simple_index_size(counts.counts[static_cast<std::uint8_t>(cli_table_id_t::type_def)]) * 2;
        case cli_table_id_t::generic_param:
            return 2 + 2 + coded_index_size(coded_index_type_or_method_def(), counts) +
                   string_index_size(heaps);
        case cli_table_id_t::method_spec:
            return coded_index_size(coded_index_method_def_or_ref(), counts) + blob_index_size(heaps);
        case cli_table_id_t::generic_param_constraint:
            return simple_index_size(counts.counts[static_cast<std::uint8_t>(cli_table_id_t::generic_param)]) +
                   coded_index_size(coded_index_type_def_or_ref(), counts);
        default:
            return 0;
    }
}

std::string read_string_heap(const std::vector<std::uint8_t>& heap, std::uint32_t index,
                              std::uint64_t max_bytes) {
    if (index == 0 || index >= heap.size())
        return {};
    std::string result;
    std::uint64_t offset = index;
    while (offset < heap.size()) {
        const auto byte = heap[offset];
        if (byte == 0)
            break;
        result.push_back(static_cast<char>(byte));
        if (result.size() > max_bytes)
            return {};
        ++offset;
    }
    return result;
}

std::vector<std::uint8_t> read_blob_heap(const std::vector<std::uint8_t>& heap, std::uint32_t index) {
    if (index == 0 || index >= heap.size())
        return {};
    std::uint64_t offset = index;
    std::uint32_t length = 0;
    if (offset >= heap.size())
        return {};
    const auto first = heap[offset];
    if ((first & 0x80u) == 0) {
        length = first & 0x7Fu;
        offset += 1;
    } else if ((first & 0xC0u) == 0x80u) {
        if (offset + 1 >= heap.size())
            return {};
        length = ((static_cast<std::uint32_t>(first) & 0x3Fu) << 8) |
                 static_cast<std::uint32_t>(heap[offset + 1]);
        offset += 2;
    } else if ((first & 0xE0u) == 0xC0u) {
        if (offset + 3 >= heap.size())
            return {};
        length = ((static_cast<std::uint32_t>(first) & 0x1Fu) << 24) |
                 (static_cast<std::uint32_t>(heap[offset + 1]) << 16) |
                 (static_cast<std::uint32_t>(heap[offset + 2]) << 8) |
                 static_cast<std::uint32_t>(heap[offset + 3]);
        offset += 4;
    } else {
        return {};
    }
    if (offset + length > heap.size())
        return {};
    return {heap.begin() + static_cast<std::ptrdiff_t>(offset),
            heap.begin() + static_cast<std::ptrdiff_t>(offset + length)};
}

class cli_metadata_parser_t {
public:
    cli_metadata_parser_t(std::vector<std::uint8_t> data, std::uint64_t metadata_offset,
                          std::shared_ptr<const pe_image_t> pe_image,
                          const cli_metadata_parse_limits_t& limits,
                          const cancellation_token_t& cancel)
        : data_(std::move(data)), metadata_offset_(metadata_offset),
          pe_image_(std::move(pe_image)), limits_(limits), cancel_(cancel) {}

    workspace_result_t<cli_metadata_t> parse() {
        if (!parse_root_header() || !parse_streams() || !parse_table_header() ||
            !parse_tables() || !parse_method_bodies())
            return workspace_result_t<cli_metadata_t>::failure(std::move(error_));
        result_.pe_image = pe_image_;
        return workspace_result_t<cli_metadata_t>::success(std::move(result_));
    }

private:
    bool fail(workspace_error_code_t code, std::string message, std::string phase,
              std::optional<std::uint64_t> offset = {}, std::optional<std::uint64_t> size = {}) {
        if (!failed_) {
            error_ = cli_error(code, std::move(message), std::move(phase), offset, size);
            failed_ = true;
        }
        return false;
    }

    bool poll(const char* phase) {
        if (!cancel_.stop_requested())
            return true;
        if (!failed_) {
            error_ = cli_stop_error(
                cancel_, "CLI metadata parsing cancelled", phase);
            failed_ = true;
        }
        return false;
    }

    bool require(std::uint64_t offset, std::uint64_t size, const char* phase) {
        if (!span_within(offset, size, data_.size()))
            return fail(workspace_error_code_t::out_of_range,
                        "CLI metadata structure exceeds input bounds", phase, offset, size);
        return true;
    }

    bool u32_at(std::uint64_t offset, std::uint32_t& value, const char* phase) {
        if (!require(offset, 4, phase)) return false;
        value = read_u32_le(data_.data() + offset);
        return true;
    }

    bool u16_at(std::uint64_t offset, std::uint16_t& value, const char* phase) {
        if (!require(offset, 2, phase)) return false;
        value = read_u16_le(data_.data() + offset);
        return true;
    }

    bool parse_root_header() {
        if (!poll("cli.root")) return false;
        if (!require(0, 16, "cli.root")) return false;
        result_.header.magic = read_u32_le(data_.data());
        if (result_.header.magic != cli_metadata_magic)
            return fail(workspace_error_code_t::unsupported_format,
                        "CLI metadata root magic is invalid", "cli.root", 0, 4);
        result_.header.major_version = read_u16_le(data_.data() + 4);
        result_.header.minor_version = read_u16_le(data_.data() + 6);
        result_.header.version_length = read_u32_le(data_.data() + 12);
        if (result_.header.version_length > limits_.max_string_heap_bytes)
            return fail(workspace_error_code_t::limit_exceeded,
                        "CLI metadata version string exceeds limit", "cli.root", 12, 4);
        const std::uint64_t version_padded = (result_.header.version_length + 3u) & ~3u;
        const std::uint64_t flags_offset = 16 + version_padded;
        if (!require(16, version_padded, "cli.root")) return false;
        result_.header.version_string.assign(
            reinterpret_cast<const char*>(data_.data() + 16),
            std::min<std::uint64_t>(result_.header.version_length, version_padded));
        const auto null_pos = result_.header.version_string.find('\0');
        if (null_pos != std::string::npos)
            result_.header.version_string.resize(null_pos);
        if (!require(flags_offset, 4, "cli.root")) return false;
        result_.header.flags = read_u16_le(data_.data() + flags_offset);
        result_.header.stream_count = read_u16_le(data_.data() + flags_offset + 2);
        if (result_.header.stream_count > limits_.max_streams)
            return fail(workspace_error_code_t::limit_exceeded,
                        "CLI metadata stream count exceeds limit", "cli.root",
                        flags_offset + 2, 2);
        std::uint64_t cursor = flags_offset + 4;
        result_.header.streams.reserve(result_.header.stream_count);
        for (std::uint16_t index = 0; index < result_.header.stream_count; ++index) {
            if (!poll("cli.root")) return false;
            if (!require(cursor, 8, "cli.root")) return false;
            cli_stream_header_t stream;
            stream.offset = read_u32_le(data_.data() + cursor);
            stream.size = read_u32_le(data_.data() + cursor + 4);
            cursor += 8;
            std::string name;
            while (cursor < data_.size()) {
                if (!require(cursor, 1, "cli.root")) return false;
                const auto byte = data_[cursor++];
                if (byte == 0) {
                    if (name.empty())
                        break;
                    cursor = (cursor + 3u) & ~3u;
                    break;
                }
                name.push_back(static_cast<char>(byte));
                if (name.size() > 32)
                    return fail(workspace_error_code_t::malformed_image,
                                "CLI metadata stream name is too long", "cli.root", cursor, 1);
            }
            stream.name = std::move(name);
            if (stream.offset >= data_.size())
                return fail(workspace_error_code_t::malformed_image,
                            "CLI metadata stream offset is out of range", "cli.root", cursor, 4);
            result_.header.streams.push_back(std::move(stream));
        }
        result_.header.root_offset = metadata_offset_;
        result_.header.root_size = data_.size();
        return true;
    }

    const cli_stream_header_t* find_stream(const char* name) const {
        for (const auto& stream : result_.header.streams) {
            if (stream.name == name)
                return &stream;
        }
        return nullptr;
    }

    bool parse_streams() {
        const auto* strings_stream = find_stream("#Strings");
        if (strings_stream != nullptr) {
            if (!require(strings_stream->offset, strings_stream->size, "cli.strings"))
                return false;
            string_heap_.assign(data_.data() + strings_stream->offset,
                                data_.data() + strings_stream->offset + strings_stream->size);
        }
        const auto* blob_stream = find_stream("#Blob");
        if (blob_stream != nullptr) {
            if (!require(blob_stream->offset, blob_stream->size, "cli.blob"))
                return false;
            blob_heap_.assign(data_.data() + blob_stream->offset,
                              data_.data() + blob_stream->offset + blob_stream->size);
        }
        const auto* guid_stream = find_stream("#GUID");
        if (guid_stream != nullptr) {
            if (!require(guid_stream->offset, guid_stream->size, "cli.guid"))
                return false;
            guid_heap_.assign(data_.data() + guid_stream->offset,
                              data_.data() + guid_stream->offset + guid_stream->size);
        }
        const auto* tables_stream = find_stream("#~");
        if (tables_stream == nullptr)
            tables_stream = find_stream("#-");
        if (tables_stream == nullptr)
            return fail(workspace_error_code_t::malformed_image,
                        "CLI metadata tables stream is absent", "cli.tables");
        if (!require(tables_stream->offset, tables_stream->size, "cli.tables"))
            return false;
        tables_raw_.assign(data_.data() + tables_stream->offset,
                           data_.data() + tables_stream->offset + tables_stream->size);
        result_.tables_raw = tables_raw_;
        tables_offset_ = tables_stream->offset;
        return true;
    }

    bool parse_table_header() {
        if (tables_raw_.size() < 24)
            return fail(workspace_error_code_t::malformed_image,
                        "CLI metadata tables stream is too small", "cli.tables", tables_offset_, tables_raw_.size());
        cli_byte_reader_t reader{tables_raw_.data(), tables_raw_.size(), 0};
        std::uint32_t reserved = 0;
        if (!reader.u32(reserved, "cli.tables")) return false;
        std::uint8_t tables_major = 0;
        std::uint8_t tables_minor = 0;
        if (!reader.u8(tables_major, "cli.tables")) return false;
        if (!reader.u8(tables_minor, "cli.tables")) return false;
        result_.table_counts.tables_major = tables_major;
        result_.table_counts.tables_minor = tables_minor;
        if (!reader.u8(result_.table_counts.heap_sizes, "cli.tables")) return false;
        std::uint8_t reserved_byte = 0;
        if (!reader.u8(reserved_byte, "cli.tables")) return false;
        if (!reader.u64(result_.table_counts.valid_mask, "cli.tables")) return false;
        if (!reader.u64(result_.table_counts.sorted_mask, "cli.tables")) return false;
        heaps_.large_strings = (result_.table_counts.heap_sizes & cli_heap_sizes_large_strings) != 0;
        heaps_.large_guid = (result_.table_counts.heap_sizes & cli_heap_sizes_large_guid) != 0;
        heaps_.large_blob = (result_.table_counts.heap_sizes & cli_heap_sizes_large_blob) != 0;
        std::uint64_t row_counts_offset = reader.offset;
        std::uint32_t present_count = 0;
        for (std::uint32_t bit = 0; bit < 64; ++bit) {
            if ((result_.table_counts.valid_mask >> bit) & 1ull) {
                if (!reader.u32(result_.table_counts.counts[bit], "cli.tables"))
                    return false;
                if (result_.table_counts.counts[bit] > limits_.max_table_rows)
                    return fail(workspace_error_code_t::limit_exceeded,
                                "CLI metadata table row count exceeds limit", "cli.tables",
                                row_counts_offset, 4);
                ++present_count;
            }
        }
        result_.table_counts.table_data_offset = reader.offset;
        return true;
    }

    bool read_string_index(cli_byte_reader_t& reader, std::string& value, const char* phase) {
        std::uint32_t index = 0;
        if (heaps_.large_strings) {
            if (!reader.u32(index, phase)) return false;
        } else {
            std::uint16_t short_index = 0;
            if (!reader.u16(short_index, phase)) return false;
            index = short_index;
        }
        value = read_string_heap(string_heap_, index, limits_.max_string_heap_bytes);
        return true;
    }

    bool read_blob_heap_index(cli_byte_reader_t& reader, std::uint32_t& index, const char* phase) {
        if (heaps_.large_blob) {
            if (!reader.u32(index, phase)) return false;
        } else {
            std::uint16_t short_index = 0;
            if (!reader.u16(short_index, phase)) return false;
            index = short_index;
        }
        return true;
    }

    bool read_blob_index(cli_byte_reader_t& reader, std::vector<std::uint8_t>& value, const char* phase) {
        std::uint32_t index = 0;
        if (!read_blob_heap_index(reader, index, phase)) return false;
        value = read_blob_heap(blob_heap_, index);
        return true;
    }

    bool read_guid_index(cli_byte_reader_t& reader, std::uint32_t& index, const char* phase) {
        if (heaps_.large_guid) {
            if (!reader.u32(index, phase)) return false;
        } else {
            std::uint16_t short_index = 0;
            if (!reader.u16(short_index, phase)) return false;
            index = short_index;
        }
        return true;
    }

    bool read_simple_index(cli_byte_reader_t& reader, std::uint32_t& index,
                           std::uint32_t table_rows, const char* phase) {
        if (table_rows > 0xFFFFu) {
            if (!reader.u32(index, phase)) return false;
        } else {
            std::uint16_t short_index = 0;
            if (!reader.u16(short_index, phase)) return false;
            index = short_index;
        }
        return true;
    }

    bool read_coded_index(cli_byte_reader_t& reader, std::uint32_t& raw,
                          const cli_coded_index_info_t& info, const char* phase) {
        const auto size = coded_index_size(info, result_.table_counts);
        if (size == 4) {
            if (!reader.u32(raw, phase)) return false;
        } else {
            std::uint16_t short_raw = 0;
            if (!reader.u16(short_raw, phase)) return false;
            raw = short_raw;
        }
        return true;
    }

    bool parse_tables() {
        std::uint64_t cursor = result_.table_counts.table_data_offset;
        for (std::uint32_t bit = 0; bit < 64; ++bit) {
            if (!((result_.table_counts.valid_mask >> bit) & 1ull))
                continue;
            const auto table_id = static_cast<std::uint8_t>(bit);
            const auto row_count = result_.table_counts.counts[bit];
            const auto row_size = table_row_size(table_id, heaps_, result_.table_counts);
            if (row_size == 0)
                return fail(workspace_error_code_t::malformed_image,
                            "CLI metadata table has an unknown layout", "cli.tables",
                            tables_offset_ + cursor, 0);
            const auto table_bytes = static_cast<std::uint64_t>(row_count) * row_size;
            if (!span_within(cursor, table_bytes, tables_raw_.size()))
                return fail(workspace_error_code_t::out_of_range,
                            "CLI metadata table extends beyond the tables stream", "cli.tables",
                            tables_offset_ + cursor, table_bytes);
            const std::uint64_t table_start = cursor;
            if (!parse_single_table(table_id, row_count, row_size, table_start))
                return false;
            cursor += table_bytes;
        }
        return true;
    }

    bool parse_single_table(std::uint8_t table_id, std::uint32_t row_count,
                             std::uint32_t row_size, std::uint64_t table_start) {
        if (!poll("cli.tables")) return false;
        switch (static_cast<cli_table_id_t>(table_id)) {
            case cli_table_id_t::module:
                return parse_module_table(table_start, row_count, row_size);
            case cli_table_id_t::type_ref:
                return parse_type_ref_table(table_start, row_count, row_size);
            case cli_table_id_t::type_def:
                return parse_type_def_table(table_start, row_count, row_size);
            case cli_table_id_t::field:
                return parse_field_table(table_start, row_count, row_size);
            case cli_table_id_t::method_def:
                return parse_method_def_table(table_start, row_count, row_size);
            case cli_table_id_t::param:
                return parse_param_table(table_start, row_count, row_size);
            case cli_table_id_t::member_ref:
                return parse_member_ref_table(table_start, row_count, row_size);
            case cli_table_id_t::custom_attribute:
                return parse_custom_attribute_table(table_start, row_count, row_size);
            case cli_table_id_t::assembly:
                return parse_assembly_table(table_start, row_count, row_size);
            case cli_table_id_t::assembly_ref:
                return parse_assembly_ref_table(table_start, row_count, row_size);
            case cli_table_id_t::manifest_resource:
                return parse_manifest_resource_table(table_start, row_count, row_size);
            case cli_table_id_t::nested_class:
                return parse_nested_class_table(table_start, row_count, row_size);
            case cli_table_id_t::generic_param:
                return parse_generic_param_table(table_start, row_count, row_size);
            case cli_table_id_t::method_spec:
                return parse_method_spec_table(table_start, row_count, row_size);
            default:
                return true;
        }
    }

    bool parse_module_table(std::uint64_t start, std::uint32_t count, std::uint32_t row_size) {
        for (std::uint32_t row = 0; row < count; ++row) {
            cli_byte_reader_t reader{tables_raw_.data() + start + static_cast<std::size_t>(row) * row_size,
                                      row_size, 0};
            cli_module_row_t module;
            if (!reader.u16(module.generation, "cli.module")) return false;
            if (!read_string_index(reader, module.name, "cli.module")) return false;
            if (!read_guid_index(reader, module.mvid_index, "cli.module")) return false;
            if (!read_guid_index(reader, module.enc_id_index, "cli.module")) return false;
            if (!read_guid_index(reader, module.enc_base_id_index, "cli.module")) return false;
            result_.module = std::move(module);
        }
        return true;
    }

    bool parse_type_ref_table(std::uint64_t start, std::uint32_t count, std::uint32_t row_size) {
        result_.type_refs.reserve(count);
        for (std::uint32_t row = 0; row < count; ++row) {
            if (!poll("cli.type_ref")) return false;
            cli_byte_reader_t reader{tables_raw_.data() + start + static_cast<std::size_t>(row) * row_size,
                                      row_size, 0};
            cli_type_ref_row_t type_ref;
            std::uint32_t resolution_scope_raw = 0;
            if (!read_coded_index(reader, resolution_scope_raw, coded_index_resolution_scope(), "cli.type_ref"))
                return false;
            if (!decode_coded_index(resolution_scope_raw, coded_index_resolution_scope(),
                                     type_ref.resolution_scope_tag, type_ref.resolution_scope_index))
                return fail(workspace_error_code_t::malformed_image,
                            "CLI TypeRef has an invalid resolution scope tag", "cli.type_ref",
                            start + static_cast<std::size_t>(row) * row_size, row_size);
            if (!read_string_index(reader, type_ref.type_name, "cli.type_ref")) return false;
            if (!read_string_index(reader, type_ref.type_namespace, "cli.type_ref")) return false;
            if (type_ref.resolution_scope_tag == 2) {
                const auto asm_ref_index = type_ref.resolution_scope_index;
                if (asm_ref_index > 0 && asm_ref_index <= result_.assembly_refs.size())
                    type_ref.assembly_ref_name = result_.assembly_refs[asm_ref_index - 1].name;
            }
            result_.type_refs.push_back(std::move(type_ref));
        }
        return true;
    }

    bool parse_type_def_table(std::uint64_t start, std::uint32_t count, std::uint32_t row_size) {
        result_.type_defs.reserve(count);
        for (std::uint32_t row = 0; row < count; ++row) {
            if (!poll("cli.type_def")) return false;
            cli_byte_reader_t reader{tables_raw_.data() + start + static_cast<std::size_t>(row) * row_size,
                                      row_size, 0};
            cli_type_def_row_t type_def;
            if (!reader.u32(type_def.flags, "cli.type_def")) return false;
            if (!read_string_index(reader, type_def.type_name, "cli.type_def")) return false;
            if (!read_string_index(reader, type_def.type_namespace, "cli.type_def")) return false;
            std::uint32_t extends_raw = 0;
            if (!read_coded_index(reader, extends_raw, coded_index_type_def_or_ref(), "cli.type_def"))
                return false;
            if (!decode_coded_index(extends_raw, coded_index_type_def_or_ref(),
                                     type_def.extends_tag, type_def.extends_index))
                return fail(workspace_error_code_t::malformed_image,
                            "CLI TypeDef has an invalid extends tag", "cli.type_def",
                            start + static_cast<std::size_t>(row) * row_size, row_size);
            if (!read_simple_index(reader, type_def.field_list_index,
                                   result_.table_counts.counts[static_cast<std::uint8_t>(cli_table_id_t::field)],
                                   "cli.type_def")) return false;
            if (!read_simple_index(reader, type_def.method_list_index,
                                   result_.table_counts.counts[static_cast<std::uint8_t>(cli_table_id_t::method_def)],
                                   "cli.type_def")) return false;
            type_def.is_interface = (type_def.flags & 0x20u) != 0;
            type_def.is_abstract = (type_def.flags & 0x80u) != 0;
            type_def.is_sealed = (type_def.flags & 0x100u) != 0;
            const auto row_index_value = row + 1;
            if (type_def.extends_tag == 0 && type_def.extends_index > 0 && type_def.extends_index <= result_.type_defs.size()) {
                const auto& base = result_.type_defs[type_def.extends_index - 1];
                type_def.base_type_name = base.type_namespace.empty()
                    ? base.type_name : base.type_namespace + "." + base.type_name;
            } else if (type_def.extends_tag == 1 && type_def.extends_index > 0 && type_def.extends_index <= result_.type_refs.size()) {
                const auto& base = result_.type_refs[type_def.extends_index - 1];
                type_def.base_type_name = base.type_namespace.empty()
                    ? base.type_name : base.type_namespace + "." + base.type_name;
            }
            result_.type_defs.push_back(std::move(type_def));
        }
        for (const auto& nested : result_.nested_classes) {
            if (nested.nested_class_index > 0 && nested.nested_class_index <= result_.type_defs.size() &&
                nested.enclosing_class_index > 0 && nested.enclosing_class_index <= result_.type_defs.size()) {
                result_.type_defs[nested.nested_class_index - 1].is_nested = true;
            }
        }
        return true;
    }

    bool parse_field_table(std::uint64_t start, std::uint32_t count, std::uint32_t row_size) {
        result_.fields.reserve(count);
        for (std::uint32_t row = 0; row < count; ++row) {
            if (!poll("cli.field")) return false;
            cli_byte_reader_t reader{tables_raw_.data() + start + static_cast<std::size_t>(row) * row_size,
                                      row_size, 0};
            cli_field_row_t field;
            if (!reader.u16(field.flags, "cli.field")) return false;
            if (!read_string_index(reader, field.name, "cli.field")) return false;
            if (!read_blob_index(reader, field.signature_blob, "cli.field")) return false;
            field.is_static = (field.flags & 0x10u) != 0;
            field.is_literal = (field.flags & 0x40u) != 0;
            field.is_init_only = (field.flags & 0x20u) != 0;
            const auto token = cli_metadata_token_t(
                (static_cast<std::uint32_t>(cli_table_id_t::field) << 24) | (row + 1));
            field.declaring_type_token = token.token;
            result_.fields.push_back(std::move(field));
        }
        return true;
    }

    bool parse_method_def_table(std::uint64_t start, std::uint32_t count, std::uint32_t row_size) {
        result_.method_defs.reserve(count);
        for (std::uint32_t row = 0; row < count; ++row) {
            if (!poll("cli.method_def")) return false;
            cli_byte_reader_t reader{tables_raw_.data() + start + static_cast<std::size_t>(row) * row_size,
                                      row_size, 0};
            cli_method_def_row_t method;
            if (!reader.u32(method.rva, "cli.method_def")) return false;
            if (!reader.u16(method.impl_flags, "cli.method_def")) return false;
            if (!reader.u16(method.flags, "cli.method_def")) return false;
            if (!read_string_index(reader, method.name, "cli.method_def")) return false;
            if (!read_blob_index(reader, method.signature_blob, "cli.method_def")) return false;
            if (!read_simple_index(reader, method.param_list_index,
                                   result_.table_counts.counts[static_cast<std::uint8_t>(cli_table_id_t::param)],
                                   "cli.method_def")) return false;
            method.is_static = (method.flags & 0x0010u) != 0;
            method.is_abstract = (method.flags & 0x0400u) != 0;
            method.is_virtual = (method.flags & 0x0040u) != 0;
            method.is_native = (method.impl_flags & 0x0008u) != 0;
            method.has_body = method.rva != 0 && !method.is_abstract && !method.is_native;
            const auto token = cli_metadata_token_t(
                (static_cast<std::uint32_t>(cli_table_id_t::method_def) << 24) | (row + 1));
            method.declaring_type_token = token.token;
            result_.method_defs.push_back(std::move(method));
        }
        return true;
    }

    bool parse_param_table(std::uint64_t start, std::uint32_t count, std::uint32_t row_size) {
        result_.params.reserve(count);
        for (std::uint32_t row = 0; row < count; ++row) {
            cli_byte_reader_t reader{tables_raw_.data() + start + static_cast<std::size_t>(row) * row_size,
                                      row_size, 0};
            cli_param_row_t param;
            if (!reader.u16(param.flags, "cli.param")) return false;
            if (!reader.u16(param.sequence, "cli.param")) return false;
            if (!read_string_index(reader, param.name, "cli.param")) return false;
            result_.params.push_back(std::move(param));
        }
        return true;
    }

    bool parse_member_ref_table(std::uint64_t start, std::uint32_t count, std::uint32_t row_size) {
        result_.member_refs.reserve(count);
        for (std::uint32_t row = 0; row < count; ++row) {
            if (!poll("cli.member_ref")) return false;
            cli_byte_reader_t reader{tables_raw_.data() + start + static_cast<std::size_t>(row) * row_size,
                                      row_size, 0};
            cli_member_ref_row_t member_ref;
            std::uint32_t class_raw = 0;
            if (!read_coded_index(reader, class_raw, coded_index_member_ref_parent(), "cli.member_ref"))
                return false;
            if (!decode_coded_index(class_raw, coded_index_member_ref_parent(),
                                     member_ref.class_tag, member_ref.class_index))
                return fail(workspace_error_code_t::malformed_image,
                            "CLI MemberRef has an invalid class tag", "cli.member_ref",
                            start + static_cast<std::size_t>(row) * row_size, row_size);
            if (!read_string_index(reader, member_ref.name, "cli.member_ref")) return false;
            if (!read_blob_index(reader, member_ref.signature_blob, "cli.member_ref")) return false;
            if (member_ref.class_tag == 0 && member_ref.class_index <= result_.type_defs.size()) {
                const auto& td = result_.type_defs[member_ref.class_index - 1];
                member_ref.declaring_type_name = td.type_namespace.empty()
                    ? td.type_name : td.type_namespace + "." + td.type_name;
                member_ref.reference_kind = managed_reference_kind_t::type_reference;
            } else if (member_ref.class_tag == 1 && member_ref.class_index <= result_.type_refs.size()) {
                const auto& tr = result_.type_refs[member_ref.class_index - 1];
                member_ref.declaring_type_name = tr.type_namespace.empty()
                    ? tr.type_name : tr.type_namespace + "." + tr.type_name;
                member_ref.reference_kind = managed_reference_kind_t::type_reference;
            }
            result_.member_refs.push_back(std::move(member_ref));
        }
        return true;
    }

    bool parse_custom_attribute_table(std::uint64_t start, std::uint32_t count, std::uint32_t row_size) {
        result_.custom_attributes.reserve(count);
        for (std::uint32_t row = 0; row < count; ++row) {
            if (!poll("cli.custom_attribute")) return false;
            cli_byte_reader_t reader{tables_raw_.data() + start + static_cast<std::size_t>(row) * row_size,
                                      row_size, 0};
            cli_custom_attribute_row_t ca;
            std::uint32_t parent_raw = 0;
            if (!read_coded_index(reader, parent_raw, coded_index_has_custom_attribute(), "cli.custom_attribute"))
                return false;
            if (!decode_coded_index(parent_raw, coded_index_has_custom_attribute(),
                                     ca.parent_tag, ca.parent_index))
                return fail(workspace_error_code_t::malformed_image,
                            "CLI CustomAttribute has an invalid parent tag", "cli.custom_attribute",
                            start + static_cast<std::size_t>(row) * row_size, row_size);
            std::uint32_t type_raw = 0;
            if (!read_coded_index(reader, type_raw, coded_index_custom_attribute_type(), "cli.custom_attribute"))
                return false;
            if (!decode_coded_index(type_raw, coded_index_custom_attribute_type(),
                                     ca.type_tag, ca.type_index))
                return fail(workspace_error_code_t::malformed_image,
                            "CLI CustomAttribute has an invalid type tag", "cli.custom_attribute",
                            start + static_cast<std::size_t>(row) * row_size, row_size);
            if (!read_blob_index(reader, ca.value_blob, "cli.custom_attribute")) return false;
            if (ca.parent_tag < coded_index_has_custom_attribute().table_ids.size()) {
                const auto parent_table = coded_index_has_custom_attribute().table_ids[ca.parent_tag];
                ca.parent_token = (static_cast<std::uint32_t>(parent_table) << 24) | ca.parent_index;
            }
            result_.custom_attributes.push_back(std::move(ca));
        }
        return true;
    }

    bool parse_assembly_table(std::uint64_t start, std::uint32_t count, std::uint32_t row_size) {
        for (std::uint32_t row = 0; row < count; ++row) {
            cli_byte_reader_t reader{tables_raw_.data() + start + static_cast<std::size_t>(row) * row_size,
                                      row_size, 0};
            cli_assembly_row_t assembly;
            if (!reader.u32(assembly.hash_alg_id, "cli.assembly")) return false;
            std::uint16_t major_version = 0;
            std::uint16_t minor_version = 0;
            std::uint16_t build_number = 0;
            std::uint16_t revision_number = 0;
            if (!reader.u16(major_version, "cli.assembly")) return false;
            if (!reader.u16(minor_version, "cli.assembly")) return false;
            if (!reader.u16(build_number, "cli.assembly")) return false;
            if (!reader.u16(revision_number, "cli.assembly")) return false;
            assembly.major_version = major_version;
            assembly.minor_version = minor_version;
            assembly.build_number = build_number;
            assembly.revision_number = revision_number;
            if (!reader.u32(assembly.flags, "cli.assembly")) return false;
            if (!read_blob_index(reader, assembly.public_key_blob, "cli.assembly")) return false;
            if (!read_string_index(reader, assembly.name, "cli.assembly")) return false;
            if (!read_string_index(reader, assembly.culture, "cli.assembly")) return false;
            result_.assembly = std::move(assembly);
        }
        return true;
    }

    bool parse_assembly_ref_table(std::uint64_t start, std::uint32_t count, std::uint32_t row_size) {
        result_.assembly_refs.reserve(count);
        for (std::uint32_t row = 0; row < count; ++row) {
            cli_byte_reader_t reader{tables_raw_.data() + start + static_cast<std::size_t>(row) * row_size,
                                      row_size, 0};
            cli_assembly_ref_row_t asm_ref;
            if (!reader.u16(asm_ref.major_version, "cli.assembly_ref")) return false;
            if (!reader.u16(asm_ref.minor_version, "cli.assembly_ref")) return false;
            if (!reader.u16(asm_ref.build_number, "cli.assembly_ref")) return false;
            if (!reader.u16(asm_ref.revision_number, "cli.assembly_ref")) return false;
            if (!reader.u32(asm_ref.flags, "cli.assembly_ref")) return false;
            if (!read_blob_index(reader, asm_ref.public_key_or_token_blob, "cli.assembly_ref")) return false;
            if (!read_string_index(reader, asm_ref.name, "cli.assembly_ref")) return false;
            if (!read_string_index(reader, asm_ref.culture, "cli.assembly_ref")) return false;
            if (!read_blob_heap_index(reader, asm_ref.hash_value_index, "cli.assembly_ref")) return false;
            result_.assembly_refs.push_back(std::move(asm_ref));
        }
        return true;
    }

    bool parse_manifest_resource_table(std::uint64_t start, std::uint32_t count, std::uint32_t row_size) {
        result_.manifest_resources.reserve(count);
        for (std::uint32_t row = 0; row < count; ++row) {
            if (!poll("cli.manifest_resource")) return false;
            cli_byte_reader_t reader{tables_raw_.data() + start + static_cast<std::size_t>(row) * row_size,
                                      row_size, 0};
            cli_manifest_resource_row_t resource;
            if (!reader.u32(resource.offset, "cli.manifest_resource")) return false;
            if (!reader.u32(resource.flags, "cli.manifest_resource")) return false;
            if (!read_string_index(reader, resource.name, "cli.manifest_resource")) return false;
            std::uint32_t impl_raw = 0;
            if (!read_coded_index(reader, impl_raw, coded_index_implementation(), "cli.manifest_resource"))
                return false;
            if (!decode_coded_index(impl_raw, coded_index_implementation(),
                                     resource.implementation_tag, resource.implementation_index))
                return fail(workspace_error_code_t::malformed_image,
                            "CLI ManifestResource has an invalid implementation tag",
                            "cli.manifest_resource",
                            start + static_cast<std::size_t>(row) * row_size, row_size);
            result_.manifest_resources.push_back(std::move(resource));
        }
        return true;
    }

    bool parse_nested_class_table(std::uint64_t start, std::uint32_t count, std::uint32_t row_size) {
        result_.nested_classes.reserve(count);
        for (std::uint32_t row = 0; row < count; ++row) {
            cli_byte_reader_t reader{tables_raw_.data() + start + static_cast<std::size_t>(row) * row_size,
                                      row_size, 0};
            cli_nested_class_row_t nested;
            const auto type_def_rows = result_.table_counts.counts[static_cast<std::uint8_t>(cli_table_id_t::type_def)];
            if (!read_simple_index(reader, nested.nested_class_index, type_def_rows, "cli.nested_class"))
                return false;
            if (!read_simple_index(reader, nested.enclosing_class_index, type_def_rows, "cli.nested_class"))
                return false;
            result_.nested_classes.push_back(std::move(nested));
        }
        return true;
    }

    bool parse_generic_param_table(std::uint64_t start, std::uint32_t count, std::uint32_t row_size) {
        result_.generic_params.reserve(count);
        for (std::uint32_t row = 0; row < count; ++row) {
            if (!poll("cli.generic_param")) return false;
            cli_byte_reader_t reader{tables_raw_.data() + start + static_cast<std::size_t>(row) * row_size,
                                      row_size, 0};
            cli_generic_param_row_t gp;
            if (!reader.u16(gp.number, "cli.generic_param")) return false;
            if (!reader.u16(gp.flags, "cli.generic_param")) return false;
            std::uint32_t owner_raw = 0;
            if (!read_coded_index(reader, owner_raw, coded_index_type_or_method_def(), "cli.generic_param"))
                return false;
            if (!decode_coded_index(owner_raw, coded_index_type_or_method_def(),
                                     gp.owner_tag, gp.owner_index))
                return fail(workspace_error_code_t::malformed_image,
                            "CLI GenericParam has an invalid owner tag", "cli.generic_param",
                            start + static_cast<std::size_t>(row) * row_size, row_size);
            if (!read_string_index(reader, gp.name, "cli.generic_param")) return false;
            result_.generic_params.push_back(std::move(gp));
        }
        return true;
    }

    bool parse_method_spec_table(std::uint64_t start, std::uint32_t count, std::uint32_t row_size) {
        result_.method_specs.reserve(count);
        for (std::uint32_t row = 0; row < count; ++row) {
            cli_byte_reader_t reader{tables_raw_.data() + start + static_cast<std::size_t>(row) * row_size,
                                      row_size, 0};
            cli_method_spec_row_t spec;
            std::uint32_t method_raw = 0;
            if (!read_coded_index(reader, method_raw, coded_index_method_def_or_ref(), "cli.method_spec"))
                return false;
            if (!decode_coded_index(method_raw, coded_index_method_def_or_ref(),
                                     spec.method_tag, spec.method_index))
                return fail(workspace_error_code_t::malformed_image,
                            "CLI MethodSpec has an invalid method tag", "cli.method_spec",
                            start + static_cast<std::size_t>(row) * row_size, row_size);
            if (!read_blob_index(reader, spec.instantiation_blob, "cli.method_spec")) return false;
            result_.method_specs.push_back(std::move(spec));
        }
        return true;
    }

    bool parse_method_bodies() {
        if (!pe_image_) return true;
        for (std::uint32_t row = 0; row < static_cast<std::uint32_t>(result_.method_defs.size()); ++row) {
            if (!poll("cli.method_body")) return false;
            const auto& method_def = result_.method_defs[row];
            if (!method_def.has_body || method_def.rva == 0)
                continue;
            auto file_offset_result = pe_image_->rva_to_file_offset(method_def.rva);
            if (!file_offset_result)
                continue;
            const auto file_offset = file_offset_result.value();
            if (!span_within(file_offset, 1, data_.size()))
                continue;
            cli_method_body_t body;
            body.method_token = (static_cast<std::uint32_t>(cli_table_id_t::method_def) << 24) | (row + 1);
            std::uint8_t header_byte = 0;
            if (!require(file_offset, 1, "cli.method_body")) return false;
            header_byte = data_[file_offset];
            if ((header_byte & 0x03u) == cli_method_head_tiny_format) {
                body.is_fat = false;
                body.offset = file_offset;
                body.size = 1 + (header_byte >> 2u);
                body.max_stack = 0;
                body.local_token = 0;
                if (!span_within(file_offset, body.size, data_.size()))
                    continue;
                body.code_bytes.assign(data_.data() + file_offset + 1,
                                       data_.data() + file_offset + body.size);
            } else if ((header_byte & 0x03u) == cli_method_head_fat_format) {
                if (!span_within(file_offset, 12, data_.size()))
                    continue;
                const auto flags_size = read_u16_le(data_.data() + file_offset);
                body.is_fat = true;
                body.max_stack = read_u16_le(data_.data() + file_offset + 2);
                const auto code_size = read_u32_le(data_.data() + file_offset + 4);
                body.local_token = read_u32_le(data_.data() + file_offset + 8);
                body.offset = file_offset + 12;
                body.size = 12ULL + code_size;
                if (!span_within(body.offset, code_size, data_.size()))
                    continue;
                body.code_bytes.assign(data_.data() + body.offset,
                                       data_.data() + body.offset + code_size);
                if (body.local_token != 0) {
                    const auto local_blob_index = body.local_token & 0x00FFFFFFu;
                    body.local_signature_blob = read_blob_heap(blob_heap_, local_blob_index);
                }
                if ((flags_size & cli_method_head_more_sects) != 0 && code_size > 0) {
                    const auto aligned_code_end = (body.offset + code_size + 3u) & ~3u;
                    if (span_within(aligned_code_end, 4, data_.size())) {
                        if (!parse_exception_sections(aligned_code_end, body))
                            return false;
                    }
                }
            } else {
                continue;
            }
            total_code_bytes_ += body.code_bytes.size();
            if (total_code_bytes_ > limits_.max_total_code_bytes)
                return fail(workspace_error_code_t::limit_exceeded,
                            "CLI metadata cumulative code bytes exceed limit", "cli.method_body",
                            file_offset, body.size);
            result_.method_bodies.push_back(std::move(body));
            if (result_.method_bodies.size() >= limits_.max_method_bodies)
                return fail(workspace_error_code_t::limit_exceeded,
                            "CLI metadata method body count exceeds limit", "cli.method_body",
                            file_offset, 0);
        }
        return true;
    }

    bool parse_exception_sections(std::uint64_t section_offset, cli_method_body_t& body) {
        std::uint64_t cursor = section_offset;
        while (span_within(cursor, 4, data_.size())) {
            const auto flags = data_[cursor];
            if (flags == 0)
                break;
            const bool is_fat = (flags & cli_cor_section_fat_format) != 0;
            const bool more = (flags & cli_cor_section_more_sects) != 0;
            std::uint32_t section_size = 0;
            if (is_fat) {
                section_size = (static_cast<std::uint32_t>(data_[cursor + 1]) << 8) |
                               (static_cast<std::uint32_t>(data_[cursor + 2]) << 16) |
                               (static_cast<std::uint32_t>(flags) << 24);
                section_size &= 0x00FFFFFFu;
                section_size |= (static_cast<std::uint32_t>(data_[cursor + 3]) << 24);
            } else {
                section_size = static_cast<std::uint32_t>(data_[cursor + 1]) |
                               (static_cast<std::uint32_t>(data_[cursor + 2]) << 8);
            }
            const auto data_start = cursor + (is_fat ? 4 : 4);
            if (!span_within(data_start, section_size, data_.size()))
                break;
            if ((flags & cli_cor_section_eh_table) != 0) {
                const auto clause_size = is_fat ? 24u : 12u;
                const auto clause_count = section_size / clause_size;
                if (clause_count > limits_.max_exception_clauses_per_method)
                    return fail(workspace_error_code_t::limit_exceeded,
                                "CLI method exception clause count exceeds limit", "cli.method_body",
                                data_start, section_size);
                for (std::uint32_t clause_index = 0; clause_index < clause_count; ++clause_index) {
                    const auto clause_offset = data_start + static_cast<std::uint64_t>(clause_index) * clause_size;
                    cli_exception_clause_t clause;
                    if (is_fat) {
                        clause.flags = read_u32_le(data_.data() + clause_offset);
                        clause.try_offset = read_u32_le(data_.data() + clause_offset + 4);
                        clause.try_length = read_u32_le(data_.data() + clause_offset + 8);
                        clause.handler_offset = read_u32_le(data_.data() + clause_offset + 12);
                        clause.handler_length = read_u32_le(data_.data() + clause_offset + 16);
                        clause.class_token_or_filter_offset = read_u32_le(data_.data() + clause_offset + 20);
                    } else {
                        clause.flags = static_cast<std::uint32_t>(data_[clause_offset]) |
                                       (static_cast<std::uint32_t>(data_[clause_offset + 1]) << 8) |
                                       (static_cast<std::uint32_t>(data_[clause_offset + 2]) << 16);
                        clause.try_offset = read_u32_le(data_.data() + clause_offset + 4);
                        clause.try_length = data_[clause_offset + 8];
                        clause.handler_offset = read_u32_le(data_.data() + clause_offset + 9);
                        clause.handler_length = data_[clause_offset + 13];
                        clause.class_token_or_filter_offset = read_u32_le(data_.data() + clause_offset + 16) & 0x00FFFFFFu;
                    }
                    clause.is_filter = clause.flags == 0x01u;
                    clause.is_catch_all = (clause.flags == 0x00u && clause.class_token_or_filter_offset == 0u);
                    if (clause.flags == 0x00u && clause.class_token_or_filter_offset != 0) {
                        clause.catch_type_token = clause.class_token_or_filter_offset;
                        const auto type_def_row = clause.class_token_or_filter_offset & 0x00FFFFFFu;
                        if (type_def_row > 0 && type_def_row <= result_.type_defs.size()) {
                            const auto& td = result_.type_defs[type_def_row - 1];
                            clause.catch_type_name = td.type_namespace.empty()
                                ? td.type_name : td.type_namespace + "." + td.type_name;
                        }
                    }
                    clause.is_finally = clause.flags == 0x02u;
                    body.exception_clauses.push_back(std::move(clause));
                }
            }
            if (!more)
                break;
            cursor = data_start + ((section_size + 3u) & ~3u);
        }
        return true;
    }

    std::vector<std::uint8_t> data_;
    std::uint64_t metadata_offset_ = 0;
    std::shared_ptr<const pe_image_t> pe_image_;
    const cli_metadata_parse_limits_t& limits_;
    const cancellation_token_t& cancel_;
    cli_metadata_t result_;
    workspace_error_t error_;
    bool failed_ = false;
    std::vector<std::uint8_t> string_heap_;
    std::vector<std::uint8_t> blob_heap_;
    std::vector<std::uint8_t> guid_heap_;
    std::vector<std::uint8_t> tables_raw_;
    std::uint64_t tables_offset_ = 0;
    cli_heap_sizes_t heaps_{};
    std::uint64_t total_code_bytes_ = 0;
};

std::string build_fully_qualified_name(const std::string& ns, const std::string& name,
                                        const std::vector<cli_nested_class_row_t>& nested,
                                        const std::vector<cli_type_def_row_t>& type_defs,
                                        std::uint32_t type_def_index) {
    std::string result = ns.empty() ? name : ns + "." + name;
    for (const auto& nc : nested) {
        if (nc.nested_class_index == type_def_index + 1 && nc.enclosing_class_index > 0 &&
            nc.enclosing_class_index <= type_defs.size()) {
            const auto& enclosing = type_defs[nc.enclosing_class_index - 1];
            const auto enclosing_name = build_fully_qualified_name(
                enclosing.type_namespace, enclosing.type_name, nested, type_defs,
                nc.enclosing_class_index - 1);
            result = enclosing_name + "/" + name;
            break;
        }
    }
    return result;
}

std::uint32_t count_generic_params_for_type(const std::vector<cli_generic_param_row_t>& gps,
                                              std::uint32_t type_def_index) {
    std::uint32_t count = 0;
    for (const auto& gp : gps) {
        if (gp.owner_tag == 0 && gp.owner_index == type_def_index + 1)
            ++count;
    }
    return count;
}

std::uint32_t count_generic_params_for_method(const std::vector<cli_generic_param_row_t>& gps,
                                                 std::uint32_t method_def_index) {
    std::uint32_t count = 0;
    for (const auto& gp : gps) {
        if (gp.owner_tag == 1 && gp.owner_index == method_def_index + 1)
            ++count;
    }
    return count;
}

std::string signature_blob_to_hex(const std::vector<std::uint8_t>& blob) {
    static constexpr char hex_chars[] = "0123456789ABCDEF";
    std::string result;
    result.reserve(blob.size() * 2);
    for (const auto byte : blob) {
        result.push_back(hex_chars[byte >> 4]);
        result.push_back(hex_chars[byte & 0x0F]);
    }
    return result;
}

}

workspace_result_t<cli_metadata_t>
parse_cli_metadata(const byte_provider_t& provider,
                   const cli_metadata_parse_limits_t& limits,
                   const cancellation_token_t& cancel) {
    if (cancel.stop_requested())
        return workspace_result_t<cli_metadata_t>::failure(
            cli_stop_error(cancel, "CLI metadata parsing cancelled", "cli.init"));
    auto pe_result = parse_pe_image(provider, {}, cancel);
    if (!pe_result)
        return workspace_result_t<cli_metadata_t>::failure(std::move(pe_result.error()));
    auto pe_image = pe_result.take_value();
    if (pe_image->directories().size() <= cli_pe_cli_directory_index)
        return workspace_result_t<cli_metadata_t>::failure(
            cli_error(workspace_error_code_t::malformed_image,
                      "PE image does not contain a CLI metadata directory", "cli.init"));
    const auto& cli_dir = pe_image->directories()[cli_pe_cli_directory_index];
    if (cli_dir.rva == 0 || cli_dir.size == 0)
        return workspace_result_t<cli_metadata_t>::failure(
            cli_error(workspace_error_code_t::malformed_image,
                      "CLI metadata directory is empty", "cli.init"));
    auto cli_header_offset_result = pe_image->rva_to_file_offset(cli_dir.rva, cli_dir.size);
    if (!cli_header_offset_result)
        return workspace_result_t<cli_metadata_t>::failure(std::move(cli_header_offset_result.error()));
    const auto cli_header_offset = cli_header_offset_result.value();
    auto cli_header_result = provider.read_vector(cli_header_offset, 72, 72, cancel);
    if (!cli_header_result)
        return workspace_result_t<cli_metadata_t>::failure(std::move(cli_header_result.error()));
    const auto& cli_header = cli_header_result.value();
    if (cli_header.size() < 72)
        return workspace_result_t<cli_metadata_t>::failure(
            cli_error(workspace_error_code_t::malformed_image,
                      "CLI header is truncated", "cli.init", cli_header_offset, cli_header.size()));
    const auto metadata_rva = read_u32_le(cli_header.data() + 8);
    const auto metadata_size = read_u32_le(cli_header.data() + 12);
    if (metadata_rva == 0 || metadata_size == 0)
        return workspace_result_t<cli_metadata_t>::failure(
            cli_error(workspace_error_code_t::malformed_image,
                      "CLI metadata directory RVA is invalid", "cli.init", cli_header_offset + 8, 8));
    if (metadata_size > limits.max_metadata_bytes)
        return workspace_result_t<cli_metadata_t>::failure(
            cli_error(workspace_error_code_t::limit_exceeded,
                      "CLI metadata size exceeds limit", "cli.init", cli_header_offset + 12, 4));
    auto metadata_offset_result = pe_image->rva_to_file_offset(metadata_rva, metadata_size);
    if (!metadata_offset_result)
        return workspace_result_t<cli_metadata_t>::failure(std::move(metadata_offset_result.error()));
    const auto metadata_offset = metadata_offset_result.value();
    auto metadata_result = provider.read_vector(metadata_offset, metadata_size, limits.max_metadata_bytes, cancel);
    if (!metadata_result)
        return workspace_result_t<cli_metadata_t>::failure(std::move(metadata_result.error()));
    const auto entry_point_token = read_u32_le(cli_header.data() + 20);
    const auto resources_rva = read_u32_le(cli_header.data() + 24);
    const auto resources_size = read_u32_le(cli_header.data() + 28);
    cli_metadata_parser_t parser(metadata_result.take_value(), metadata_offset, pe_image, limits, cancel);
    auto parsed = parser.parse();
    if (!parsed)
        return parsed;
    auto metadata = parsed.take_value();
    metadata.metadata_rva = metadata_rva;
    metadata.metadata_size = metadata_size;
    metadata.image_base = pe_image->image_base();
    metadata.entry_point_token = entry_point_token;
    metadata.resources_rva = resources_rva;
    metadata.resources_size = resources_size;
    return workspace_result_t<cli_metadata_t>::success(std::move(metadata));
}

workspace_result_t<managed_artifact_t>
build_cli_artifact(const cli_metadata_t& metadata,
                   const byte_provider_t& provider,
                   const managed_reader_limits_t& limits,
                   const cancellation_token_t& cancel) {
    managed_artifact_t artifact;
    artifact.kind = managed_artifact_kind_t::cli_metadata;
    artifact.module_identity.kind = managed_artifact_kind_t::cli_metadata;
    artifact.module_identity.artifact_offset = metadata.metadata_rva;
    artifact.module_identity.artifact_size = metadata.metadata_size;
    artifact.module_identity.module_name = metadata.module.name;
    if (metadata.assembly) {
        artifact.module_identity.assembly_name = metadata.assembly->name;
        artifact.module_identity.version = std::to_string(metadata.assembly->major_version) + "." +
            std::to_string(metadata.assembly->minor_version) + "." +
            std::to_string(metadata.assembly->build_number) + "." +
            std::to_string(metadata.assembly->revision_number);
        artifact.module_identity.assembly_flags = metadata.assembly->flags;
    } else {
        artifact.module_identity.assembly_name = metadata.module.name;
    }
    artifact.module_identity.entry_point_token = metadata.entry_point_token;
    artifact.module_identity.runtime_major = metadata.header.major_version;
    artifact.module_identity.runtime_minor = metadata.header.minor_version;
    auto hash_result = provider.compute_content_sha256(cancel);
    if (!hash_result)
        return workspace_result_t<managed_artifact_t>::failure(hash_result.error());
    artifact.module_identity.artifact_hash = hash_result.take_value();

    std::vector<managed_type_identity_t> type_identities;
    type_identities.reserve(metadata.type_defs.size());
    for (std::uint32_t row = 0; row < static_cast<std::uint32_t>(metadata.type_defs.size()); ++row) {
        if (cancel.stop_requested())
            return workspace_result_t<managed_artifact_t>::failure(
                cli_stop_error(cancel, "CLI artifact building cancelled", "cli.build"));
        const auto& td = metadata.type_defs[row];
        managed_type_identity_t type;
        type.namespace_name = td.type_namespace;
        type.type_name = td.type_name;
        type.fully_qualified_name = build_fully_qualified_name(
            td.type_namespace, td.type_name, metadata.nested_classes, metadata.type_defs, row);
        type.metadata_token = (static_cast<std::uint32_t>(cli_table_id_t::type_def) << 24) | (row + 1);
        type.generic_arity = count_generic_params_for_type(metadata.generic_params, row);
        type.is_interface = td.is_interface;
        type.is_abstract = td.is_abstract;
        type.is_final = td.is_sealed;
        type.is_nested = td.is_nested;
        type.access_flags = td.flags;
        if (td.extends_index > 0) {
            if (td.extends_tag == 0 && td.extends_index <= metadata.type_defs.size())
                type.base_type_name = metadata.type_defs[td.extends_index - 1].type_name;
            else if (td.extends_tag == 1 && td.extends_index <= metadata.type_refs.size())
                type.base_type_name = metadata.type_refs[td.extends_index - 1].type_name;
        }
        if (!td.base_type_name.empty())
            type.base_type_name = td.base_type_name;
        const auto next_field_index = (row + 1 < metadata.type_defs.size())
            ? metadata.type_defs[row + 1].field_list_index
            : static_cast<std::uint32_t>(metadata.fields.size() + 1);
        for (std::uint32_t fi = td.field_list_index; fi < next_field_index && fi <= metadata.fields.size(); ++fi) {
            type.field_tokens.push_back(
                (static_cast<std::uint32_t>(cli_table_id_t::field) << 24) | fi);
        }
        const auto next_method_index = (row + 1 < metadata.type_defs.size())
            ? metadata.type_defs[row + 1].method_list_index
            : static_cast<std::uint32_t>(metadata.method_defs.size() + 1);
        for (std::uint32_t mi = td.method_list_index; mi < next_method_index && mi <= metadata.method_defs.size(); ++mi) {
            type.method_tokens.push_back(
                (static_cast<std::uint32_t>(cli_table_id_t::method_def) << 24) | mi);
        }
        type_identities.push_back(std::move(type));
        if (type_identities.size() >= limits.max_types)
            return workspace_result_t<managed_artifact_t>::failure(
                cli_error(workspace_error_code_t::limit_exceeded,
                          "CLI type identity count exceeds limit", "cli.build"));
    }
    artifact.types = std::move(type_identities);

    std::vector<managed_method_identity_t> method_identities;
    method_identities.reserve(metadata.method_defs.size());
    for (std::uint32_t row = 0; row < static_cast<std::uint32_t>(metadata.method_defs.size()); ++row) {
        if (cancel.stop_requested())
            return workspace_result_t<managed_artifact_t>::failure(
                cli_stop_error(cancel, "CLI artifact building cancelled", "cli.build"));
        const auto& md = metadata.method_defs[row];
        managed_method_identity_t method;
        method.method_name = md.name;
        method.method_signature = signature_blob_to_hex(md.signature_blob);
        method.metadata_token = (static_cast<std::uint32_t>(cli_table_id_t::method_def) << 24) | (row + 1);
        method.method_index = row;
        method.generic_arity = count_generic_params_for_method(metadata.generic_params, row);
        method.access_flags = md.flags;
        method.is_static = md.is_static;
        method.is_abstract = md.is_abstract;
        method.is_virtual = md.is_virtual;
        method.is_native = md.is_native;
        method.has_body = md.has_body;
        for (const auto& body : metadata.method_bodies) {
            if (body.method_token == method.metadata_token) {
                method.code_offset = body.offset;
                method.code_size = body.code_bytes.size();
                method.max_stack = body.max_stack;
                method.local_token = body.local_token;
                break;
            }
        }
        const auto next_param_index = (row + 1 < metadata.method_defs.size())
            ? metadata.method_defs[row + 1].param_list_index
            : static_cast<std::uint32_t>(metadata.params.size() + 1);
        for (std::uint32_t pi = md.param_list_index; pi < next_param_index && pi <= metadata.params.size(); ++pi) {
            const auto& param = metadata.params[pi - 1];
            if (param.sequence > 0)
                method.parameter_names.push_back(param.name);
        }
        for (const auto& td : metadata.type_defs) {
            const auto type_token = (static_cast<std::uint32_t>(cli_table_id_t::type_def) << 24);
            for (std::uint32_t mi = td.method_list_index; mi <= metadata.method_defs.size(); ++mi) {
                if (mi == row + 1) {
                    method.declaring_type_name = td.type_namespace.empty()
                        ? td.type_name : td.type_namespace + "." + td.type_name;
                    break;
                }
            }
            if (!method.declaring_type_name.empty())
                break;
        }
        if (!md.signature_blob.empty()) {
            managed_signature_t sig;
            sig.raw_signature = method.method_signature;
            sig.method_token = method.metadata_token;
            sig.artifact_kind = managed_artifact_kind_t::cli_metadata;
            artifact.signatures.push_back(std::move(sig));
        }
        method_identities.push_back(std::move(method));
        if (method_identities.size() >= limits.max_methods)
            return workspace_result_t<managed_artifact_t>::failure(
                cli_error(workspace_error_code_t::limit_exceeded,
                          "CLI method identity count exceeds limit", "cli.build"));
    }
    artifact.methods = std::move(method_identities);

    std::vector<managed_field_identity_t> field_identities;
    field_identities.reserve(metadata.fields.size());
    for (std::uint32_t row = 0; row < static_cast<std::uint32_t>(metadata.fields.size()); ++row) {
        if (cancel.stop_requested())
            return workspace_result_t<managed_artifact_t>::failure(
                cli_stop_error(cancel, "CLI artifact building cancelled", "cli.build"));
        const auto& fd = metadata.fields[row];
        managed_field_identity_t field;
        field.field_name = fd.name;
        field.field_signature = signature_blob_to_hex(fd.signature_blob);
        field.metadata_token = (static_cast<std::uint32_t>(cli_table_id_t::field) << 24) | (row + 1);
        field.field_index = row;
        field.access_flags = fd.flags;
        field.is_static = fd.is_static;
        field.is_literal = fd.is_literal;
        field.is_init_only = fd.is_init_only;
        for (std::size_t type_index = 0; type_index < metadata.type_defs.size(); ++type_index) {
            const auto& td = metadata.type_defs[type_index];
            const auto next_field_index = (type_index + 1 < metadata.type_defs.size())
                ? metadata.type_defs[type_index + 1].field_list_index
                : static_cast<std::uint32_t>(metadata.fields.size() + 1);
            if (row + 1 >= td.field_list_index && row + 1 < next_field_index) {
                field.declaring_type_name = td.type_namespace.empty()
                    ? td.type_name : td.type_namespace + "." + td.type_name;
                break;
            }
        }
        field_identities.push_back(std::move(field));
        if (field_identities.size() >= limits.max_fields)
            return workspace_result_t<managed_artifact_t>::failure(
                cli_error(workspace_error_code_t::limit_exceeded,
                          "CLI field identity count exceeds limit", "cli.build"));
    }
    artifact.fields = std::move(field_identities);

    for (const auto& mr : metadata.member_refs) {
        if (artifact.member_references.size() >= limits.max_member_references)
            return workspace_result_t<managed_artifact_t>::failure(
                cli_error(workspace_error_code_t::limit_exceeded,
                          "CLI member reference count exceeds limit", "cli.build"));
        managed_member_reference_t ref;
        ref.kind = mr.reference_kind;
        ref.declaring_type_name = mr.declaring_type_name;
        ref.member_name = mr.name;
        ref.member_signature = signature_blob_to_hex(mr.signature_blob);
        ref.reference_token = (static_cast<std::uint32_t>(cli_table_id_t::member_ref) << 24) |
            (static_cast<std::uint32_t>(&mr - &metadata.member_refs[0]) + 1);
        artifact.member_references.push_back(std::move(ref));
    }

    for (const auto& body : metadata.method_bodies) {
        if (artifact.code_ranges.size() >= limits.max_code_ranges)
            return workspace_result_t<managed_artifact_t>::failure(
                cli_error(workspace_error_code_t::limit_exceeded,
                          "CLI code range count exceeds limit", "cli.build"));
        managed_code_range_t range;
        range.offset = body.offset;
        range.size = body.code_bytes.size();
        range.max_stack = body.max_stack;
        range.max_locals = 0;
        range.method_token = body.method_token;
        range.local_token = body.local_token;
        range.is_fat_format = body.is_fat;
        range.code_bytes = body.code_bytes;
        range.local_signature_blob = body.local_signature_blob;
        artifact.code_ranges.push_back(std::move(range));
        artifact.total_code_bytes += body.code_bytes.size();
        for (const auto& clause : body.exception_clauses) {
            if (artifact.exception_regions.size() >= limits.max_exception_regions)
                return workspace_result_t<managed_artifact_t>::failure(
                    cli_error(workspace_error_code_t::limit_exceeded,
                              "CLI exception region count exceeds limit", "cli.build"));
            managed_exception_region_t region;
            region.start_offset = clause.try_offset;
            region.end_offset = clause.try_offset + clause.try_length;
            region.handler_offset = clause.handler_offset;
            region.catch_type_name = clause.catch_type_name;
            region.catch_type_token = clause.catch_type_token;
            region.method_token = body.method_token;
            region.is_finally = clause.is_finally;
            region.is_filter = clause.is_filter;
            region.is_catch_all = clause.is_catch_all;
            if (clause.is_filter)
                region.filter_offset = clause.class_token_or_filter_offset;
            artifact.exception_regions.push_back(std::move(region));
        }
    }

    for (const auto& ca : metadata.custom_attributes) {
        if (artifact.annotations.size() >= limits.max_annotations)
            return workspace_result_t<managed_artifact_t>::failure(
                cli_error(workspace_error_code_t::limit_exceeded,
                          "CLI annotation count exceeds limit", "cli.build"));
        managed_annotation_t annotation;
        annotation.parent_token = ca.parent_token;
        annotation.offset = 0;
        if (ca.type_tag == 2 && ca.type_index <= metadata.method_defs.size()) {
            annotation.annotation_type = metadata.method_defs[ca.type_index - 1].name;
        } else if (ca.type_tag == 3 && ca.type_index <= metadata.member_refs.size()) {
            annotation.annotation_type = metadata.member_refs[ca.type_index - 1].name;
        }
        artifact.annotations.push_back(std::move(annotation));
    }

    for (std::size_t ri = 0; ri < metadata.manifest_resources.size(); ++ri) {
        if (artifact.resources.size() >= limits.max_resources)
            return workspace_result_t<managed_artifact_t>::failure(
                cli_error(workspace_error_code_t::limit_exceeded,
                          "CLI resource count exceeds limit", "cli.build"));
        const auto& mr = metadata.manifest_resources[ri];
        managed_resource_t resource;
        resource.name = mr.name;
        resource.offset = mr.offset;
        resource.flags = mr.flags;
        if (ri + 1 < metadata.manifest_resources.size() &&
            metadata.manifest_resources[ri + 1].offset > mr.offset) {
            resource.size = metadata.manifest_resources[ri + 1].offset - mr.offset;
        } else if (metadata.resources_size > 0 && mr.offset < metadata.resources_size) {
            resource.size = metadata.resources_size - mr.offset;
        }
        const auto impl_info = coded_index_implementation();
        if (mr.implementation_tag < impl_info.table_ids.size()) {
            const auto table_id = impl_info.table_ids[mr.implementation_tag];
            resource.implementation_token = (static_cast<std::uint32_t>(table_id) << 24) | mr.implementation_index;
        }
        if (mr.implementation_tag == 1 && mr.implementation_index <= metadata.assembly_refs.size())
            resource.file_name = metadata.assembly_refs[mr.implementation_index - 1].name;
        artifact.resources.push_back(std::move(resource));
    }

    for (const auto& asm_ref : metadata.assembly_refs) {
        managed_member_reference_t ref;
        ref.kind = managed_reference_kind_t::assembly_reference;
        ref.member_name = asm_ref.name;
        ref.assembly_reference_name = asm_ref.name;
        artifact.member_references.push_back(std::move(ref));
    }

    std::unordered_set<std::string> seen_type_names;
    for (const auto& type : artifact.types) {
        if (!seen_type_names.insert(type.fully_qualified_name).second) {
            managed_duplicate_identity_t dup;
            dup.identity_key = type.fully_qualified_name;
            dup.description = "Duplicate CLI type fully-qualified name";
            artifact.duplicate_identities.push_back(std::move(dup));
        }
    }
    std::unordered_set<std::uint32_t> seen_method_tokens;
    for (const auto& method : artifact.methods) {
        if (!seen_method_tokens.insert(method.metadata_token).second) {
            managed_duplicate_identity_t dup;
            dup.identity_key = format_cli_token(method.metadata_token);
            dup.description = "Duplicate CLI method metadata token";
            artifact.duplicate_identities.push_back(std::move(dup));
        }
    }

    if (metadata.pe_image) {
        artifact.normalized.format = metadata.pe_image->format();
        artifact.normalized.architecture = metadata.pe_image->architecture();
        artifact.normalized.architecture_mode = metadata.pe_image->architecture_mode();
        artifact.normalized.abi = metadata.pe_image->abi();
        artifact.normalized.endian = metadata.pe_image->endian();
        artifact.normalized.address_width_bits =
            metadata.pe_image->format() == format_id_t::pe32 ? 32 : 64;
        artifact.normalized.image_base = metadata.pe_image->image_base();
        artifact.normalized.image_size = metadata.pe_image->image_size();
        artifact.normalized.header_size = metadata.pe_image->headers_size();
        artifact.normalized.format_name = "cli:" + artifact.module_identity.assembly_name;
    }

    return workspace_result_t<managed_artifact_t>::success(std::move(artifact));
}

}
