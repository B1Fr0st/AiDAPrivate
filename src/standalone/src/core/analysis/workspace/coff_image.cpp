#include "coff_image.hpp"

#include "checked_range.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace aida::analysis {
namespace {

constexpr std::array<std::uint8_t, 8> archive_magic{
    static_cast<std::uint8_t>('!'), static_cast<std::uint8_t>('<'),
    static_cast<std::uint8_t>('a'), static_cast<std::uint8_t>('r'),
    static_cast<std::uint8_t>('c'), static_cast<std::uint8_t>('h'),
    static_cast<std::uint8_t>('>'), static_cast<std::uint8_t>('\n')};
constexpr std::uint64_t cancel_check_interval = 256;

workspace_error_t coff_error(std::string message, const char* phase,
                             std::optional<std::uint64_t> offset = {},
                             std::optional<std::uint64_t> size = {}) {
    auto error = make_workspace_error(workspace_error_code_t::malformed_image,
                                      std::move(message), phase);
    error.offset = offset;
    error.size = size;
    return error;
}

workspace_error_t coff_limit_error(std::string message, const char* phase,
                                   std::uint64_t value, std::uint64_t limit) {
    auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                                      std::move(message), phase);
    error.details.emplace_back("value", std::to_string(value));
    error.details.emplace_back("limit", std::to_string(limit));
    return error;
}

workspace_error_t coff_stop_error(const cancellation_token_t& cancel) {
    if (cancel.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
                                          "COFF parsing deadline exceeded", "coff_parse");
        error.deadline = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
                                      "COFF parsing cancelled", "coff_parse");
    error.cancellation = true;
    return error;
}

workspace_error_t coff_allocation_error() {
    return make_workspace_error(workspace_error_code_t::limit_exceeded,
                                "COFF parsing allocation failed", "coff_parse");
}

std::uint16_t read_u16_le(const std::uint8_t* value) noexcept {
    return static_cast<std::uint16_t>(value[0]) |
           static_cast<std::uint16_t>(static_cast<std::uint16_t>(value[1]) << 8);
}

std::uint32_t read_u32_le(const std::uint8_t* value) noexcept {
    return static_cast<std::uint32_t>(value[0]) |
           (static_cast<std::uint32_t>(value[1]) << 8) |
           (static_cast<std::uint32_t>(value[2]) << 16) |
           (static_cast<std::uint32_t>(value[3]) << 24);
}

std::uint32_t read_u32_be(const std::uint8_t* value) noexcept {
    return (static_cast<std::uint32_t>(value[0]) << 24) |
           (static_cast<std::uint32_t>(value[1]) << 16) |
           (static_cast<std::uint32_t>(value[2]) << 8) |
           static_cast<std::uint32_t>(value[3]);
}

std::uint64_t read_u64_be(const std::uint8_t* value) noexcept {
    return (static_cast<std::uint64_t>(value[0]) << 56) |
           (static_cast<std::uint64_t>(value[1]) << 48) |
           (static_cast<std::uint64_t>(value[2]) << 40) |
           (static_cast<std::uint64_t>(value[3]) << 32) |
           (static_cast<std::uint64_t>(value[4]) << 24) |
           (static_cast<std::uint64_t>(value[5]) << 16) |
           (static_cast<std::uint64_t>(value[6]) << 8) |
           static_cast<std::uint64_t>(value[7]);
}

std::int32_t read_i16_le(const std::uint8_t* value) noexcept {
    const auto raw = read_u16_le(value);
    if (raw <= static_cast<std::uint16_t>((std::numeric_limits<std::int16_t>::max)()))
        return static_cast<std::int32_t>(raw);
    return -1 - static_cast<std::int32_t>(
        static_cast<std::uint16_t>((std::numeric_limits<std::uint16_t>::max)() - raw));
}

class parse_context_t final {
public:
    parse_context_t(const coff_parse_limits_t& limits, const cancellation_token_t& cancel)
        : limits_(limits), cancel_(cancel) {}

    const coff_parse_limits_t& limits() const noexcept { return limits_; }
    const cancellation_token_t& cancel() const noexcept { return cancel_; }

    workspace_result_t<void> poll() {
        if ((visits_++ & (cancel_check_interval - 1)) == 0 && cancel_.stop_requested())
            return workspace_result_t<void>::failure(coff_stop_error(cancel_));
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> charge_metadata(std::uint64_t bytes, const char* phase) {
        if (bytes > limits_.max_total_metadata_bytes - metadata_bytes_)
            return workspace_result_t<void>::failure(coff_limit_error(
                "COFF metadata budget is exceeded", phase, bytes,
                limits_.max_total_metadata_bytes));
        metadata_bytes_ += bytes;
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> charge_string(std::uint64_t bytes, const char* phase) {
        if (bytes > limits_.max_materialized_string_bytes - string_bytes_)
            return workspace_result_t<void>::failure(coff_limit_error(
                "COFF materialized string budget is exceeded", phase, bytes,
                limits_.max_materialized_string_bytes));
        string_bytes_ += bytes;
        return workspace_result_t<void>::success();
    }

private:
    const coff_parse_limits_t& limits_;
    const cancellation_token_t& cancel_;
    std::uint64_t visits_ = 0;
    std::uint64_t metadata_bytes_ = 0;
    std::uint64_t string_bytes_ = 0;
};

class bounded_reader_t final {
public:
    bounded_reader_t(const byte_provider_t& provider, std::uint64_t base, std::uint64_t length,
                     parse_context_t& context)
        : provider_(provider), base_(base), length_(length), context_(context) {}

    std::uint64_t length() const noexcept { return length_; }
    std::uint64_t base() const noexcept { return base_; }

    workspace_result_t<void> read(std::uint64_t offset, void* destination, std::uint64_t size,
                                  const char* phase) const {
        auto stopped = context_.poll();
        if (!stopped)
            return stopped;
        auto span = validate_span(offset, size, length_, phase);
        if (!span)
            return workspace_result_t<void>::failure(std::move(span.error()));
        std::uint64_t absolute = 0;
        if (!checked_add_u64(base_, offset, absolute))
            return workspace_result_t<void>::failure(
                coff_error("COFF reader offset overflows", phase, offset, size));
        auto read = provider_.read_exact(absolute, destination, size, context_.cancel());
        if (!read)
            return workspace_result_t<void>::failure(std::move(read.error()));
        return workspace_result_t<void>::success();
    }

    workspace_result_t<std::vector<std::uint8_t>> vector(
        std::uint64_t offset, std::uint64_t size, std::uint64_t hard_limit,
        const char* phase) const {
        auto stopped = context_.poll();
        if (!stopped)
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                std::move(stopped.error()));
        if (size > hard_limit)
            return workspace_result_t<std::vector<std::uint8_t>>::failure(coff_limit_error(
                "COFF read exceeds its configured limit", phase, size, hard_limit));
        auto span = validate_span(offset, size, length_, phase);
        if (!span)
            return workspace_result_t<std::vector<std::uint8_t>>::failure(std::move(span.error()));
        std::uint64_t absolute = 0;
        if (!checked_add_u64(base_, offset, absolute))
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                coff_error("COFF reader offset overflows", phase, offset, size));
        auto bytes = provider_.read_vector(absolute, size, hard_limit, context_.cancel());
        if (!bytes)
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                std::move(bytes.error()));
        auto charge = context_.charge_metadata(size, phase);
        if (!charge)
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                std::move(charge.error()));
        return bytes;
    }

private:
    const byte_provider_t& provider_;
    std::uint64_t base_ = 0;
    std::uint64_t length_ = 0;
    parse_context_t& context_;
};

workspace_result_t<std::string> canonical_text(const std::uint8_t* bytes, std::size_t size,
                                                bool allow_empty, parse_context_t& context,
                                                const char* phase) {
    if (size > context.limits().max_name_bytes)
        return workspace_result_t<std::string>::failure(coff_limit_error(
            "COFF name exceeds its configured limit", phase, size, context.limits().max_name_bytes));
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(size);
    for (std::size_t index = 0; index < size; ++index) {
        const auto value = bytes[index];
        if (value == 0)
            return workspace_result_t<std::string>::failure(
                coff_error("COFF name contains an embedded NUL", phase));
        if (value >= 0x20 && value <= 0x7e) {
            result.push_back(static_cast<char>(value));
        } else {
            result.push_back('\\');
            result.push_back('x');
            result.push_back(hex[value >> 4]);
            result.push_back(hex[value & 0x0f]);
        }
    }
    if (result.empty() && !allow_empty)
        return workspace_result_t<std::string>::failure(coff_error("COFF name is empty", phase));
    auto charge = context.charge_string(result.size(), phase);
    if (!charge)
        return workspace_result_t<std::string>::failure(std::move(charge.error()));
    return workspace_result_t<std::string>::success(std::move(result));
}

workspace_result_t<std::uint64_t> parse_decimal(const std::uint8_t* bytes, std::size_t size,
                                                bool allow_blank, const char* phase,
                                                std::optional<std::uint64_t> offset = {}) {
    bool seen_digit = false;
    bool trailing_space = false;
    std::uint64_t result = 0;
    for (std::size_t index = 0; index < size; ++index) {
        const auto value = bytes[index];
        if (value == static_cast<std::uint8_t>(' ')) {
            if (seen_digit)
                trailing_space = true;
            continue;
        }
        if (value < static_cast<std::uint8_t>('0') || value > static_cast<std::uint8_t>('9') ||
            trailing_space) {
            return workspace_result_t<std::uint64_t>::failure(
                coff_error("COFF archive numeric field is malformed", phase, offset));
        }
        const auto digit = static_cast<std::uint64_t>(value - static_cast<std::uint8_t>('0'));
        if (result > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 10)
            return workspace_result_t<std::uint64_t>::failure(
                coff_error("COFF archive numeric field overflows", phase, offset));
        result = result * 10 + digit;
        seen_digit = true;
    }
    if (!seen_digit && !allow_blank)
        return workspace_result_t<std::uint64_t>::failure(
            coff_error("COFF archive required numeric field is empty", phase, offset));
    return workspace_result_t<std::uint64_t>::success(result);
}

workspace_result_t<std::uint64_t> parse_decimal_text(std::string_view text, const char* phase) {
    if (text.empty())
        return workspace_result_t<std::uint64_t>::failure(
            coff_error("COFF decimal text is empty", phase));
    std::uint64_t value = 0;
    for (const auto character : text) {
        if (character < '0' || character > '9')
            return workspace_result_t<std::uint64_t>::failure(
                coff_error("COFF decimal text is malformed", phase));
        const auto digit = static_cast<std::uint64_t>(character - '0');
        if (value > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 10)
            return workspace_result_t<std::uint64_t>::failure(
                coff_error("COFF decimal text overflows", phase));
        value = value * 10 + digit;
    }
    return workspace_result_t<std::uint64_t>::success(value);
}

bool all_zero(const std::uint8_t* bytes, std::size_t size) noexcept {
    for (std::size_t index = 0; index < size; ++index)
        if (bytes[index] != 0)
            return false;
    return true;
}

std::uint64_t section_alignment(std::uint32_t characteristics) noexcept {
    switch (characteristics & 0x00f00000u) {
        case 0x00100000u: return 1;
        case 0x00200000u: return 2;
        case 0x00300000u: return 4;
        case 0x00400000u: return 8;
        case 0x00500000u: return 16;
        case 0x00600000u: return 32;
        case 0x00700000u: return 64;
        case 0x00800000u: return 128;
        case 0x00900000u: return 256;
        case 0x00a00000u: return 512;
        case 0x00b00000u: return 1024;
        case 0x00c00000u: return 2048;
        case 0x00d00000u: return 4096;
        case 0x00e00000u: return 8192;
        default: return 1;
    }
}

bool align_up(std::uint64_t value, std::uint64_t alignment, std::uint64_t& out) noexcept {
    const auto mask = alignment - 1;
    std::uint64_t adjusted = 0;
    if (!checked_add_u64(value, mask, adjusted))
        return false;
    out = adjusted & ~mask;
    return true;
}

std::uint32_t section_permissions(std::uint32_t characteristics) noexcept {
    std::uint32_t result = image_permission_none;
    if ((characteristics & coff_section_mem_read) != 0 ||
        (characteristics & (coff_section_cnt_code | coff_section_cnt_initialized_data |
                            coff_section_cnt_uninitialized_data)) != 0) {
        result |= image_permission_read;
    }
    if ((characteristics & coff_section_mem_write) != 0)
        result |= image_permission_write;
    if ((characteristics & (coff_section_mem_execute | coff_section_cnt_code)) != 0)
        result |= image_permission_execute;
    if ((characteristics & coff_section_mem_discardable) != 0)
        result |= image_permission_discardable;
    return result;
}

image_symbol_binding_t symbol_binding(const coff_symbol_t& symbol) noexcept {
    if (symbol.is_weak)
        return image_symbol_binding_t::weak;
    if (symbol.storage_class == coff_storage_class_external ||
        symbol.storage_class == coff_storage_class_external_def) {
        return symbol.is_defined ? image_symbol_binding_t::global : image_symbol_binding_t::external;
    }
    return image_symbol_binding_t::local;
}

image_symbol_kind_t symbol_kind(const coff_symbol_t& symbol) noexcept {
    if (symbol.is_function)
        return image_symbol_kind_t::function;
    if (symbol.is_section_symbol)
        return image_symbol_kind_t::section;
    if (symbol.storage_class == coff_storage_class_file)
        return image_symbol_kind_t::metadata;
    return image_symbol_kind_t::object;
}

struct object_record_t {
    std::uint16_t machine = 0;
    std::uint16_t characteristics = 0;
    std::uint32_t time_date_stamp = 0;
    std::uint32_t symbol_table_offset = 0;
    std::uint32_t symbol_table_count = 0;
    std::uint64_t header_size = 0;
    std::uint64_t synthetic_image_size = 0;
    std::vector<coff_section_t> sections;
    std::vector<coff_symbol_t> symbols;
    std::vector<coff_relocation_t> relocations;
};

workspace_result_t<std::string> string_table_name(const std::vector<std::uint8_t>& table,
                                                   std::uint32_t offset,
                                                   bool allow_empty,
                                                   parse_context_t& context,
                                                   const char* phase) {
    if (table.empty() || offset < 4 || offset >= table.size())
        return workspace_result_t<std::string>::failure(
            coff_error("COFF string-table reference is invalid", phase));
    std::size_t end = offset;
    while (end < table.size() && table[end] != 0)
        ++end;
    if (end == table.size())
        return workspace_result_t<std::string>::failure(
            coff_error("COFF string-table name is unterminated", phase));
    return canonical_text(table.data() + offset, end - offset, allow_empty, context, phase);
}

workspace_result_t<std::string> section_name_from_raw(
    const std::array<std::uint8_t, 8>& raw, const std::vector<std::uint8_t>& table,
    parse_context_t& context) {
    if (raw[0] == static_cast<std::uint8_t>('/')) {
        std::size_t length = 1;
        while (length < raw.size() && raw[length] != 0)
            ++length;
        if (length < raw.size() && !all_zero(raw.data() + length, raw.size() - length))
            return workspace_result_t<std::string>::failure(
                coff_error("COFF section name has bytes after a terminator", "coff_sections"));
        auto offset = parse_decimal_text(std::string_view(
            reinterpret_cast<const char*>(raw.data() + 1), length - 1), "coff_sections");
        if (!offset || offset.value() > (std::numeric_limits<std::uint32_t>::max)())
            return workspace_result_t<std::string>::failure(offset ? coff_error(
                "COFF section string-table offset is too large", "coff_sections") : offset.error());
        return string_table_name(table, static_cast<std::uint32_t>(offset.value()), false,
                                 context, "coff_sections");
    }
    std::size_t length = 0;
    while (length < raw.size() && raw[length] != 0)
        ++length;
    if (length < raw.size() && !all_zero(raw.data() + length, raw.size() - length))
        return workspace_result_t<std::string>::failure(
            coff_error("COFF section name has bytes after a terminator", "coff_sections"));
    return canonical_text(raw.data(), length, false, context, "coff_sections");
}

workspace_result_t<std::string> symbol_name_from_raw(
    const std::array<std::uint8_t, 8>& raw, const std::vector<std::uint8_t>& table,
    parse_context_t& context) {
    if (all_zero(raw.data(), 4))
        return string_table_name(table, read_u32_le(raw.data() + 4), true, context, "coff_symbols");
    std::size_t length = 0;
    while (length < raw.size() && raw[length] != 0)
        ++length;
    if (length < raw.size() && !all_zero(raw.data() + length, raw.size() - length))
        return workspace_result_t<std::string>::failure(
            coff_error("COFF symbol name has bytes after a terminator", "coff_symbols"));
    return canonical_text(raw.data(), length, true, context, "coff_symbols");
}

workspace_result_t<object_record_t> parse_object(bounded_reader_t& reader,
                                                  parse_context_t& context) {
    if (reader.length() < sizeof(coff_file_header_t))
        return workspace_result_t<object_record_t>::failure(
            coff_error("COFF file header is truncated", "coff_header", 0,
                       sizeof(coff_file_header_t)));
    std::array<std::uint8_t, sizeof(coff_file_header_t)> header_bytes{};
    auto header_read = reader.read(0, header_bytes.data(), header_bytes.size(), "coff_header");
    if (!header_read)
        return workspace_result_t<object_record_t>::failure(std::move(header_read.error()));
    object_record_t record;
    record.machine = read_u16_le(header_bytes.data());
    const auto section_count = read_u16_le(header_bytes.data() + 2);
    record.time_date_stamp = read_u32_le(header_bytes.data() + 4);
    record.symbol_table_offset = read_u32_le(header_bytes.data() + 8);
    record.symbol_table_count = read_u32_le(header_bytes.data() + 12);
    const auto optional_size = read_u16_le(header_bytes.data() + 16);
    record.characteristics = read_u16_le(header_bytes.data() + 18);
    if (coff_machine_to_architecture(record.machine) == architecture_id_t::unknown)
        return workspace_result_t<object_record_t>::failure(make_workspace_error(
            workspace_error_code_t::unsupported_format,
            "COFF machine is unsupported", "coff_header"));
    if (optional_size != 0)
        return workspace_result_t<object_record_t>::failure(
            coff_error("COFF object has an unexpected optional header", "coff_header", 16, 2));
    if (section_count == 0)
        return workspace_result_t<object_record_t>::failure(
            coff_error("COFF object has no sections", "coff_header", 2, 2));
    if (section_count > context.limits().max_sections)
        return workspace_result_t<object_record_t>::failure(coff_limit_error(
            "COFF section count exceeds its configured limit", "coff_header", section_count,
            context.limits().max_sections));
    if (record.symbol_table_count > context.limits().max_symbols)
        return workspace_result_t<object_record_t>::failure(coff_limit_error(
            "COFF symbol count exceeds its configured limit", "coff_header",
            record.symbol_table_count, context.limits().max_symbols));
    std::uint64_t section_bytes = 0;
    if (!checked_mul_u64(section_count, sizeof(coff_section_header_t), section_bytes) ||
        !checked_add_u64(sizeof(coff_file_header_t), section_bytes, record.header_size)) {
        return workspace_result_t<object_record_t>::failure(
            coff_error("COFF section table size overflows", "coff_header"));
    }
    auto section_span = validate_span(0, record.header_size, reader.length(), "coff_sections");
    if (!section_span)
        return workspace_result_t<object_record_t>::failure(std::move(section_span.error()));
    auto section_charge = context.charge_metadata(
        static_cast<std::uint64_t>(section_count) * sizeof(coff_section_t), "coff_sections");
    if (!section_charge)
        return workspace_result_t<object_record_t>::failure(std::move(section_charge.error()));
    record.sections.reserve(section_count);
    std::vector<std::array<std::uint8_t, 8>> raw_section_names;
    raw_section_names.reserve(section_count);
    for (std::uint32_t index = 0; index < section_count; ++index) {
        auto stopped = context.poll();
        if (!stopped)
            return workspace_result_t<object_record_t>::failure(std::move(stopped.error()));
        std::uint64_t delta = 0;
        std::uint64_t offset = 0;
        if (!checked_mul_u64(index, sizeof(coff_section_header_t), delta) ||
            !checked_add_u64(sizeof(coff_file_header_t), delta, offset)) {
            return workspace_result_t<object_record_t>::failure(
                coff_error("COFF section header offset overflows", "coff_sections"));
        }
        std::array<std::uint8_t, sizeof(coff_section_header_t)> bytes{};
        auto read = reader.read(offset, bytes.data(), bytes.size(), "coff_sections");
        if (!read)
            return workspace_result_t<object_record_t>::failure(std::move(read.error()));
        coff_section_t section;
        section.index = index + 1;
        std::array<std::uint8_t, 8> raw_name{};
        std::copy_n(bytes.data(), raw_name.size(), raw_name.data());
        raw_section_names.push_back(raw_name);
        section.source_virtual_address = read_u32_le(bytes.data() + 12);
        section.raw_size = read_u32_le(bytes.data() + 16);
        section.raw_offset = read_u32_le(bytes.data() + 20);
        section.relocation_offset = read_u32_le(bytes.data() + 24);
        section.line_number_offset = read_u32_le(bytes.data() + 28);
        section.relocation_count = read_u16_le(bytes.data() + 32);
        section.line_number_count = read_u16_le(bytes.data() + 34);
        section.characteristics = read_u32_le(bytes.data() + 36);
        section.has_raw_data = section.raw_size != 0;
        if (section.raw_size != 0) {
            if (section.raw_offset == 0)
                return workspace_result_t<object_record_t>::failure(
                    coff_error("COFF section raw data has a zero offset", "coff_sections"));
            auto raw_span = validate_span(section.raw_offset, section.raw_size, reader.length(),
                                          "coff_sections");
            if (!raw_span)
                return workspace_result_t<object_record_t>::failure(std::move(raw_span.error()));
        } else if (section.raw_offset != 0) {
            return workspace_result_t<object_record_t>::failure(
                coff_error("COFF empty section has a raw-data offset", "coff_sections"));
        }
        if (section.relocation_count == 0 && section.relocation_offset != 0)
            return workspace_result_t<object_record_t>::failure(
                coff_error("COFF section has a relocation offset without relocations", "coff_sections"));
        if (section.relocation_count != 0 && section.raw_size == 0)
            return workspace_result_t<object_record_t>::failure(
                coff_error("COFF relocation section has no raw data", "coff_sections"));
        record.sections.push_back(std::move(section));
    }
    std::uint64_t synthetic_cursor = record.header_size;
    for (auto& section : record.sections) {
        if (section.raw_size == 0)
            continue;
        if (!align_up(synthetic_cursor, section_alignment(section.characteristics), synthetic_cursor))
            return workspace_result_t<object_record_t>::failure(
                coff_error("COFF synthetic section layout overflows", "coff_layout"));
        section.normalized_virtual_address = synthetic_cursor;
        if (!checked_add_u64(synthetic_cursor, section.raw_size, synthetic_cursor) ||
            synthetic_cursor > context.limits().max_synthetic_image_size) {
            return workspace_result_t<object_record_t>::failure(coff_limit_error(
                "COFF synthetic image exceeds its configured limit", "coff_layout",
                synthetic_cursor, context.limits().max_synthetic_image_size));
        }
    }
    record.synthetic_image_size = synthetic_cursor;
    if (record.symbol_table_count == 0 && record.symbol_table_offset != 0)
        return workspace_result_t<object_record_t>::failure(
            coff_error("COFF symbol-table offset is present without symbols", "coff_symbols"));
    std::vector<std::uint8_t> string_table;
    if (record.symbol_table_count != 0) {
        if (record.symbol_table_offset == 0)
            return workspace_result_t<object_record_t>::failure(
                coff_error("COFF symbol table has a zero offset", "coff_symbols"));
        std::uint64_t symbol_bytes = 0;
        std::uint64_t symbol_end = 0;
        if (!checked_mul_u64(record.symbol_table_count, sizeof(coff_symbol_t_disk), symbol_bytes) ||
            !checked_add_u64(record.symbol_table_offset, symbol_bytes, symbol_end)) {
            return workspace_result_t<object_record_t>::failure(
                coff_error("COFF symbol table size overflows", "coff_symbols"));
        }
        auto symbol_span = validate_span(record.symbol_table_offset, symbol_bytes, reader.length(),
                                         "coff_symbols");
        if (!symbol_span)
            return workspace_result_t<object_record_t>::failure(std::move(symbol_span.error()));
        if (symbol_end != reader.length()) {
            std::array<std::uint8_t, 4> size_bytes{};
            auto size_read = reader.read(symbol_end, size_bytes.data(), size_bytes.size(), "coff_strings");
            if (!size_read)
                return workspace_result_t<object_record_t>::failure(std::move(size_read.error()));
            const auto string_size = read_u32_le(size_bytes.data());
            if (string_size < 4)
                return workspace_result_t<object_record_t>::failure(
                    coff_error("COFF string table has an invalid size", "coff_strings", symbol_end, 4));
            if (string_size > context.limits().max_string_table_bytes)
                return workspace_result_t<object_record_t>::failure(coff_limit_error(
                    "COFF string table exceeds its configured limit", "coff_strings", string_size,
                    context.limits().max_string_table_bytes));
            auto table = reader.vector(symbol_end, string_size,
                                       context.limits().max_string_table_bytes, "coff_strings");
            if (!table)
                return workspace_result_t<object_record_t>::failure(std::move(table.error()));
            string_table = table.take_value();
        }
    }
    for (std::size_t index = 0; index < raw_section_names.size(); ++index) {
        auto name = section_name_from_raw(raw_section_names[index], string_table, context);
        if (!name)
            return workspace_result_t<object_record_t>::failure(std::move(name.error()));
        record.sections[index].name = name.take_value();
    }
    std::vector<std::int64_t> primary_symbols(record.symbol_table_count, -1);
    if (record.symbol_table_count != 0) {
        auto symbol_charge = context.charge_metadata(
            static_cast<std::uint64_t>(record.symbol_table_count) * sizeof(coff_symbol_t),
            "coff_symbols");
        if (!symbol_charge)
            return workspace_result_t<object_record_t>::failure(std::move(symbol_charge.error()));
        record.symbols.reserve(record.symbol_table_count);
        std::uint64_t index = 0;
        while (index < record.symbol_table_count) {
            auto stopped = context.poll();
            if (!stopped)
                return workspace_result_t<object_record_t>::failure(std::move(stopped.error()));
            std::uint64_t delta = 0;
            std::uint64_t offset = 0;
            if (!checked_mul_u64(index, sizeof(coff_symbol_t_disk), delta) ||
                !checked_add_u64(record.symbol_table_offset, delta, offset)) {
                return workspace_result_t<object_record_t>::failure(
                    coff_error("COFF symbol offset overflows", "coff_symbols"));
            }
            std::array<std::uint8_t, sizeof(coff_symbol_t_disk)> bytes{};
            auto read = reader.read(offset, bytes.data(), bytes.size(), "coff_symbols");
            if (!read)
                return workspace_result_t<object_record_t>::failure(std::move(read.error()));
            const auto auxiliary_count = bytes[17];
            std::uint64_t next_index = 0;
            if (!checked_add_u64(index, static_cast<std::uint64_t>(auxiliary_count) + 1, next_index) ||
                next_index > record.symbol_table_count) {
                return workspace_result_t<object_record_t>::failure(
                    coff_error("COFF auxiliary symbol count exceeds the symbol table", "coff_symbols",
                               offset, sizeof(coff_symbol_t_disk)));
            }
            std::array<std::uint8_t, 8> raw_name{};
            std::copy_n(bytes.data(), raw_name.size(), raw_name.data());
            auto name = symbol_name_from_raw(raw_name, string_table, context);
            if (!name)
                return workspace_result_t<object_record_t>::failure(std::move(name.error()));
            coff_symbol_t symbol;
            symbol.table_index = static_cast<std::uint32_t>(index);
            symbol.name = name.take_value();
            symbol.value = read_u32_le(bytes.data() + 8);
            symbol.section_number = read_i16_le(bytes.data() + 12);
            symbol.type = read_u16_le(bytes.data() + 14);
            symbol.storage_class = bytes[16];
            symbol.auxiliary_symbol_count = auxiliary_count;
            symbol.is_external = symbol.storage_class == coff_storage_class_external ||
                                 symbol.storage_class == coff_storage_class_external_def;
            symbol.is_weak = symbol.storage_class == coff_storage_class_weak_external;
            symbol.is_function = (symbol.type & 0x0030u) == 0x0020u ||
                                 symbol.storage_class == coff_storage_class_function;
            symbol.is_section_symbol = symbol.storage_class == coff_storage_class_section ||
                                       (symbol.storage_class == coff_storage_class_static &&
                                        symbol.section_number > 0 && symbol.value == 0);
            if (symbol.section_number > 0) {
                const auto section_index = static_cast<std::uint32_t>(symbol.section_number);
                if (section_index > record.sections.size())
                    return workspace_result_t<object_record_t>::failure(
                        coff_error("COFF symbol references an invalid section", "coff_symbols", offset,
                                   sizeof(coff_symbol_t_disk)));
                const auto& section = record.sections[section_index - 1];
                symbol.is_defined = true;
                if (section.raw_size != 0 && symbol.value < section.raw_size) {
                    std::uint64_t address = 0;
                    if (!checked_add_u64(section.normalized_virtual_address, symbol.value, address))
                        return workspace_result_t<object_record_t>::failure(
                            coff_error("COFF symbol normalized address overflows", "coff_symbols"));
                    symbol.normalized_address = address;
                }
            }
            primary_symbols[static_cast<std::size_t>(index)] =
                static_cast<std::int64_t>(record.symbols.size());
            record.symbols.push_back(std::move(symbol));
            index = next_index;
        }
    }
    std::uint64_t relocation_total = 0;
    for (auto& section : record.sections) {
        auto stopped = context.poll();
        if (!stopped)
            return workspace_result_t<object_record_t>::failure(std::move(stopped.error()));
        std::uint64_t actual_count = section.relocation_count;
        std::uint64_t table_count = actual_count;
        bool overflow = false;
        if (section.relocation_count == 0xffffu) {
            if ((section.characteristics & coff_section_lnk_nreloc_ovfl) == 0)
                return workspace_result_t<object_record_t>::failure(
                    coff_error("COFF relocation overflow count lacks its flag", "coff_relocations"));
            if (section.relocation_offset == 0)
                return workspace_result_t<object_record_t>::failure(
                    coff_error("COFF relocation overflow table has a zero offset", "coff_relocations"));
            std::array<std::uint8_t, sizeof(coff_relocation_t_disk)> count_bytes{};
            auto count_read = reader.read(section.relocation_offset, count_bytes.data(), count_bytes.size(),
                                          "coff_relocations");
            if (!count_read)
                return workspace_result_t<object_record_t>::failure(std::move(count_read.error()));
            if (read_u32_le(count_bytes.data() + 4) != 0 || read_u16_le(count_bytes.data() + 8) != 0)
                return workspace_result_t<object_record_t>::failure(
                    coff_error("COFF relocation overflow record is malformed", "coff_relocations"));
            actual_count = read_u32_le(count_bytes.data());
            if (actual_count == 0)
                return workspace_result_t<object_record_t>::failure(
                    coff_error("COFF relocation overflow count is zero", "coff_relocations"));
            if (!checked_add_u64(actual_count, 1, table_count))
                return workspace_result_t<object_record_t>::failure(
                    coff_error("COFF relocation overflow count overflows", "coff_relocations"));
            overflow = true;
        } else if ((section.characteristics & coff_section_lnk_nreloc_ovfl) != 0) {
            return workspace_result_t<object_record_t>::failure(
                coff_error("COFF relocation overflow flag has no overflow count", "coff_relocations"));
        }
        if (actual_count == 0)
            continue;
        if (actual_count > context.limits().max_relocations ||
            actual_count > context.limits().max_relocations - relocation_total) {
            return workspace_result_t<object_record_t>::failure(coff_limit_error(
                "COFF relocation count exceeds its configured limit", "coff_relocations",
                relocation_total + actual_count, context.limits().max_relocations));
        }
        if (section.relocation_offset == 0)
            return workspace_result_t<object_record_t>::failure(
                coff_error("COFF relocation table has a zero offset", "coff_relocations"));
        std::uint64_t table_size = 0;
        if (!checked_mul_u64(table_count, sizeof(coff_relocation_t_disk), table_size))
            return workspace_result_t<object_record_t>::failure(
                coff_error("COFF relocation table size overflows", "coff_relocations"));
        auto table_span = validate_span(section.relocation_offset, table_size, reader.length(),
                                        "coff_relocations");
        if (!table_span)
            return workspace_result_t<object_record_t>::failure(std::move(table_span.error()));
        auto relocation_charge = context.charge_metadata(
            actual_count * sizeof(coff_relocation_t), "coff_relocations");
        if (!relocation_charge)
            return workspace_result_t<object_record_t>::failure(std::move(relocation_charge.error()));
        for (std::uint64_t ordinal = 0; ordinal < actual_count; ++ordinal) {
            auto poll = context.poll();
            if (!poll)
                return workspace_result_t<object_record_t>::failure(std::move(poll.error()));
            std::uint64_t source_index = ordinal + (overflow ? 1 : 0);
            std::uint64_t delta = 0;
            std::uint64_t offset = 0;
            if (!checked_mul_u64(source_index, sizeof(coff_relocation_t_disk), delta) ||
                !checked_add_u64(section.relocation_offset, delta, offset)) {
                return workspace_result_t<object_record_t>::failure(
                    coff_error("COFF relocation offset overflows", "coff_relocations"));
            }
            std::array<std::uint8_t, sizeof(coff_relocation_t_disk)> bytes{};
            auto read = reader.read(offset, bytes.data(), bytes.size(), "coff_relocations");
            if (!read)
                return workspace_result_t<object_record_t>::failure(std::move(read.error()));
            coff_relocation_t relocation;
            relocation.section_index = section.index;
            relocation.virtual_address = read_u32_le(bytes.data());
            relocation.symbol_table_index = read_u32_le(bytes.data() + 4);
            relocation.type = read_u16_le(bytes.data() + 8);
            if (relocation.virtual_address >= section.raw_size)
                return workspace_result_t<object_record_t>::failure(
                    coff_error("COFF relocation is outside its section raw data", "coff_relocations",
                               offset, sizeof(coff_relocation_t_disk)));
            if (relocation.symbol_table_index >= primary_symbols.size() ||
                primary_symbols[relocation.symbol_table_index] < 0) {
                return workspace_result_t<object_record_t>::failure(
                    coff_error("COFF relocation references an auxiliary or absent symbol", "coff_relocations",
                               offset, sizeof(coff_relocation_t_disk)));
            }
            std::uint64_t address = 0;
            if (!checked_add_u64(section.normalized_virtual_address, relocation.virtual_address,
                                 address)) {
                return workspace_result_t<object_record_t>::failure(
                    coff_error("COFF relocation normalized address overflows", "coff_relocations"));
            }
            relocation.normalized_address = address;
            const auto target_index = static_cast<std::size_t>(
                primary_symbols[relocation.symbol_table_index]);
            const auto& target = record.symbols[target_index];
            if (target.normalized_address)
                relocation.target_address = *target.normalized_address;
            record.relocations.push_back(std::move(relocation));
        }
        relocation_total += actual_count;
        section.relocation_count = static_cast<std::uint32_t>(actual_count);
    }
    return workspace_result_t<object_record_t>::success(std::move(record));
}

workspace_result_t<coff_import_object_t> parse_import_object(bounded_reader_t& reader,
                                                              parse_context_t& context) {
    if (reader.length() < sizeof(coff_import_object_header_t))
        return workspace_result_t<coff_import_object_t>::failure(
            coff_error("COFF import object header is truncated", "coff_import", 0,
                       sizeof(coff_import_object_header_t)));
    std::array<std::uint8_t, sizeof(coff_import_object_header_t)> bytes{};
    auto read = reader.read(0, bytes.data(), bytes.size(), "coff_import");
    if (!read)
        return workspace_result_t<coff_import_object_t>::failure(std::move(read.error()));
    if (read_u16_le(bytes.data()) != 0 || read_u16_le(bytes.data() + 2) != 0xffffu)
        return workspace_result_t<coff_import_object_t>::failure(
            coff_error("COFF import object signature is invalid", "coff_import"));
    coff_import_object_t result;
    result.version = read_u16_le(bytes.data() + 4);
    result.machine = read_u16_le(bytes.data() + 6);
    result.time_date_stamp = read_u32_le(bytes.data() + 8);
    const auto data_size = read_u32_le(bytes.data() + 12);
    result.ordinal_or_hint = read_u16_le(bytes.data() + 16);
    const auto flags = read_u16_le(bytes.data() + 18);
    if ((flags & ~0x001fu) != 0 || ((flags >> 2) & 0x7u) > 4)
        return workspace_result_t<coff_import_object_t>::failure(
            coff_error("COFF import object flags are invalid", "coff_import"));
    if (coff_machine_to_architecture(result.machine) == architecture_id_t::unknown)
        return workspace_result_t<coff_import_object_t>::failure(make_workspace_error(
            workspace_error_code_t::unsupported_format,
            "COFF import object machine is unsupported", "coff_import"));
    result.import_type = static_cast<std::uint8_t>(flags & 0x3u);
    result.name_type = static_cast<std::uint8_t>((flags >> 2) & 0x7u);
    const auto remaining = reader.length() - sizeof(coff_import_object_header_t);
    if (data_size != remaining)
        return workspace_result_t<coff_import_object_t>::failure(
            coff_error("COFF import object data size does not match its member size", "coff_import",
                       sizeof(coff_import_object_header_t), data_size));
    if (data_size == 0 || data_size > context.limits().max_string_table_bytes)
        return workspace_result_t<coff_import_object_t>::failure(coff_limit_error(
            "COFF import object string data exceeds its configured limit", "coff_import", data_size,
            context.limits().max_string_table_bytes));
    auto data = reader.vector(sizeof(coff_import_object_header_t), data_size,
                              context.limits().max_string_table_bytes, "coff_import");
    if (!data)
        return workspace_result_t<coff_import_object_t>::failure(std::move(data.error()));
    const auto& text = data.value();
    const auto symbol_end = std::find(text.begin(), text.end(), static_cast<std::uint8_t>(0));
    if (symbol_end == text.end())
        return workspace_result_t<coff_import_object_t>::failure(
            coff_error("COFF import object symbol name is unterminated", "coff_import"));
    const auto library_begin = symbol_end + 1;
    const auto library_end = std::find(library_begin, text.end(), static_cast<std::uint8_t>(0));
    if (library_end == text.end() || library_end + 1 != text.end())
        return workspace_result_t<coff_import_object_t>::failure(
            coff_error("COFF import object library name is malformed", "coff_import"));
    if (symbol_end != text.begin()) {
        auto symbol = canonical_text(text.data(), static_cast<std::size_t>(symbol_end - text.begin()),
                                     false, context, "coff_import");
        if (!symbol)
            return workspace_result_t<coff_import_object_t>::failure(std::move(symbol.error()));
        result.symbol_name = symbol.take_value();
    }
    auto library = canonical_text(text.data() + (library_begin - text.begin()),
                                  static_cast<std::size_t>(library_end - library_begin), false,
                                  context, "coff_import");
    if (!library)
        return workspace_result_t<coff_import_object_t>::failure(std::move(library.error()));
    result.library_name = library.take_value();
    result.size = reader.length();
    return workspace_result_t<coff_import_object_t>::success(std::move(result));
}

address_t make_address(std::uint64_t value, std::uint16_t machine) noexcept {
    return address_t{address_space_id_t::relative_virtual, value,
                     coff_machine_to_architecture(machine), coff_machine_to_mode(machine)};
}

workspace_result_t<workspace_image_t> normalize_object(const object_record_t& record,
                                                        const byte_provider_t& provider,
                                                        const cancellation_token_t& cancel) {
    workspace_image_t output;
    output.format = format_id_t::coff;
    output.architecture = coff_machine_to_architecture(record.machine);
    output.architecture_mode = coff_machine_to_mode(record.machine);
    output.abi = coff_machine_to_abi(record.machine);
    output.endian = endian_t::little;
    output.address_width_bits = output.architecture == architecture_id_t::x86 ||
                                        output.architecture == architecture_id_t::arm ||
                                        output.architecture == architecture_id_t::mips ||
                                        output.architecture == architecture_id_t::ppc ||
                                        output.architecture == architecture_id_t::riscv32
                                    ? 32 : 64;
    output.image_size = record.synthetic_image_size;
    output.header_size = record.header_size;
    output.format_name = "coff_object";
    output.provider_size = provider.size();
    output.member = provider.member_metadata();
    image_address_mapping_t header_mapping;
    header_mapping.source_start = 0;
    header_mapping.target_start = 0;
    header_mapping.size = record.header_size;
    header_mapping.permissions = image_permission_read;
    output.address_mappings.push_back(header_mapping);
    for (const auto& section : record.sections) {
        if (cancel.stop_requested())
            return workspace_result_t<workspace_image_t>::failure(coff_stop_error(cancel));
        if (section.raw_size == 0)
            continue;
        image_section_t normalized_section;
        normalized_section.index = section.index;
        normalized_section.name = section.name;
        normalized_section.virtual_address = section.normalized_virtual_address;
        normalized_section.virtual_size = section.raw_size;
        normalized_section.file_offset = section.raw_offset;
        normalized_section.file_size = section.raw_size;
        normalized_section.flags = section.characteristics;
        normalized_section.permissions = section_permissions(section.characteristics);
        output.sections.push_back(normalized_section);
        image_segment_t segment;
        segment.index = section.index;
        segment.name = section.name;
        segment.virtual_address = section.normalized_virtual_address;
        segment.virtual_size = section.raw_size;
        segment.file_offset = section.raw_offset;
        segment.file_size = section.raw_size;
        segment.alignment = section_alignment(section.characteristics);
        segment.flags = section.characteristics;
        segment.permissions = normalized_section.permissions;
        output.segments.push_back(std::move(segment));
        image_address_mapping_t mapping;
        mapping.source_start = section.raw_offset;
        mapping.target_start = section.normalized_virtual_address;
        mapping.size = section.raw_size;
        mapping.permissions = normalized_section.permissions;
        output.address_mappings.push_back(mapping);
    }
    for (const auto& source : record.symbols) {
        if (cancel.stop_requested())
            return workspace_result_t<workspace_image_t>::failure(coff_stop_error(cancel));
        image_symbol_t symbol;
        symbol.ordinal = source.table_index;
        symbol.name = source.name;
        symbol.address = make_address(0, record.machine);
        if (source.normalized_address) {
            symbol.address = make_address(*source.normalized_address, record.machine);
            symbol.defined = source.is_defined;
        }
        symbol.kind = symbol_kind(source);
        symbol.binding = symbol_binding(source);
        output.symbols.push_back(std::move(symbol));
    }
    for (const auto& source : record.relocations) {
        if (cancel.stop_requested())
            return workspace_result_t<workspace_image_t>::failure(coff_stop_error(cancel));
        if (!source.normalized_address)
            return workspace_result_t<workspace_image_t>::failure(
                coff_error("COFF relocation lacks a normalized address", "coff_normalize"));
        image_relocation_t relocation;
        relocation.address = make_address(*source.normalized_address, record.machine);
        relocation.type = source.type;
        if (source.target_address)
            relocation.target = make_address(*source.target_address, record.machine);
        output.relocations.push_back(std::move(relocation));
    }
    auto validation = validate_workspace_image(output, {}, false, cancel);
    if (!validation)
        return workspace_result_t<workspace_image_t>::failure(std::move(validation.error()));
    return workspace_result_t<workspace_image_t>::success(std::move(output));
}

workspace_result_t<workspace_image_t> normalize_import(const coff_import_object_t& import,
                                                        const byte_provider_t& provider,
                                                        const cancellation_token_t& cancel) {
    workspace_image_t output;
    output.format = format_id_t::coff;
    output.architecture = coff_machine_to_architecture(import.machine);
    output.architecture_mode = coff_machine_to_mode(import.machine);
    output.abi = coff_machine_to_abi(import.machine);
    output.endian = endian_t::little;
    output.address_width_bits = output.architecture == architecture_id_t::x86 ||
                                        output.architecture == architecture_id_t::arm ||
                                        output.architecture == architecture_id_t::mips ||
                                        output.architecture == architecture_id_t::ppc ||
                                        output.architecture == architecture_id_t::riscv32
                                    ? 32 : 64;
    output.image_size = provider.size();
    output.header_size = sizeof(coff_import_object_header_t);
    output.format_name = "coff_import_object";
    output.provider_size = provider.size();
    output.member = provider.member_metadata();
    image_section_t section;
    section.name = "import_object";
    section.virtual_size = output.image_size;
    section.file_size = output.image_size;
    section.permissions = image_permission_read;
    output.sections.push_back(section);
    image_segment_t segment;
    segment.name = "import_object";
    segment.virtual_size = output.image_size;
    segment.file_size = output.image_size;
    segment.permissions = image_permission_read;
    output.segments.push_back(segment);
    image_address_mapping_t mapping;
    mapping.size = output.image_size;
    mapping.permissions = image_permission_read;
    output.address_mappings.push_back(mapping);
    image_import_t normalized_import;
    normalized_import.library = import.library_name;
    normalized_import.name = import.symbol_name;
    normalized_import.lookup_address = make_address(0, import.machine);
    normalized_import.address = make_address(0, import.machine);
    output.imports.push_back(normalized_import);
    image_symbol_t symbol;
    symbol.name = import.library_name;
    symbol.name.push_back('!');
    if (import.symbol_name)
        symbol.name.append(*import.symbol_name);
    else
        symbol.name.append("#").append(std::to_string(import.ordinal_or_hint));
    symbol.address = normalized_import.address;
    symbol.kind = image_symbol_kind_t::import_symbol;
    symbol.binding = image_symbol_binding_t::external;
    output.symbols.push_back(std::move(symbol));
    auto validation = validate_workspace_image(output, {}, false, cancel);
    if (!validation)
        return workspace_result_t<workspace_image_t>::failure(std::move(validation.error()));
    return workspace_result_t<workspace_image_t>::success(std::move(output));
}

struct archive_member_raw_t {
    coff_archive_member_t member;
    std::string raw_name;
    bool is_long_name_reference = false;
    bool is_bsd_name = false;
    std::uint64_t long_name_offset = 0;
    std::uint64_t bsd_name_size = 0;
};

workspace_result_t<std::string> archive_header_name(const std::uint8_t* bytes,
                                                     parse_context_t& context,
                                                     std::uint64_t offset) {
    std::size_t length = 16;
    while (length != 0 && bytes[length - 1] == static_cast<std::uint8_t>(' '))
        --length;
    if (length == 0)
        return workspace_result_t<std::string>::failure(
            coff_error("COFF archive member name is empty", "coff_archive", offset, 16));
    for (std::size_t index = 0; index < length; ++index) {
        if (bytes[index] < 0x20 || bytes[index] > 0x7e)
            return workspace_result_t<std::string>::failure(
                coff_error("COFF archive member name is not ASCII", "coff_archive", offset, 16));
    }
    return canonical_text(bytes, length, false, context, "coff_archive");
}

workspace_result_t<std::string> resolve_long_archive_name(
    const std::vector<std::uint8_t>& table, std::uint64_t offset, parse_context_t& context) {
    if (offset >= table.size())
        return workspace_result_t<std::string>::failure(
            coff_error("COFF archive long-name offset is outside its table", "coff_archive"));
    std::size_t end = static_cast<std::size_t>(offset);
    while (end < table.size() && table[end] != static_cast<std::uint8_t>('\n'))
        ++end;
    if (end == table.size() || end == offset)
        return workspace_result_t<std::string>::failure(
            coff_error("COFF archive long-name entry is malformed", "coff_archive"));
    std::size_t name_end = end;
    if (name_end > offset && table[name_end - 1] == static_cast<std::uint8_t>('\r'))
        --name_end;
    if (name_end > offset && table[name_end - 1] == static_cast<std::uint8_t>('/'))
        --name_end;
    return canonical_text(table.data() + offset, name_end - static_cast<std::size_t>(offset),
                          false, context, "coff_archive");
}

workspace_result_t<std::string> parse_bsd_member_name(bounded_reader_t& reader,
                                                       std::uint64_t name_size,
                                                       parse_context_t& context) {
    if (name_size == 0 || name_size > context.limits().max_name_bytes)
        return workspace_result_t<std::string>::failure(coff_limit_error(
            "COFF archive BSD member name exceeds its configured limit", "coff_archive", name_size,
            context.limits().max_name_bytes));
    auto bytes = reader.vector(0, name_size, context.limits().max_name_bytes, "coff_archive");
    if (!bytes)
        return workspace_result_t<std::string>::failure(std::move(bytes.error()));
    return canonical_text(bytes.value().data(), bytes.value().size(), false, context, "coff_archive");
}

workspace_result_t<void> append_archive_symbol(
    const std::string& name, std::uint64_t member_offset, coff_archive_symbol_table_t table,
    const std::map<std::uint64_t, std::uint32_t>& member_by_offset,
    std::vector<coff_archive_symbol_t>& output, parse_context_t& context, const char* phase) {
    const auto member = member_by_offset.find(member_offset);
    if (member == member_by_offset.end())
        return workspace_result_t<void>::failure(
            coff_error("COFF archive symbol points outside the member table", phase, member_offset));
    auto charge = context.charge_metadata(sizeof(coff_archive_symbol_t), phase);
    if (!charge)
        return charge;
    output.push_back(coff_archive_symbol_t{name, member->second, member_offset, table});
    return workspace_result_t<void>::success();
}

workspace_result_t<std::string> archive_table_string(const std::vector<std::uint8_t>& data,
                                                      std::size_t& cursor,
                                                      parse_context_t& context,
                                                      const char* phase) {
    if (cursor >= data.size())
        return workspace_result_t<std::string>::failure(
            coff_error("COFF archive symbol-name table is truncated", phase));
    const auto begin = cursor;
    while (cursor < data.size() && data[cursor] != 0)
        ++cursor;
    if (cursor == data.size())
        return workspace_result_t<std::string>::failure(
            coff_error("COFF archive symbol name is unterminated", phase));
    auto name = canonical_text(data.data() + begin, cursor - begin, false, context, phase);
    ++cursor;
    return name;
}

workspace_result_t<void> parse_first_linker_member(
    const std::vector<std::uint8_t>& data, const std::map<std::uint64_t, std::uint32_t>& member_by_offset,
    std::vector<coff_archive_symbol_t>& output, parse_context_t& context,
    coff_archive_symbol_table_t table, bool sixty_four) {
    const char* phase = "coff_archive_linker";
    const std::size_t word_size = sixty_four ? 8 : 4;
    if (data.size() < word_size)
        return workspace_result_t<void>::failure(
            coff_error("COFF archive linker member is truncated", phase));
    const auto count = sixty_four ? read_u64_be(data.data()) : read_u32_be(data.data());
    if (count > context.limits().max_archive_symbols)
        return workspace_result_t<void>::failure(coff_limit_error(
            "COFF archive symbol count exceeds its configured limit", phase, count,
            context.limits().max_archive_symbols));
    std::uint64_t offsets_size = 0;
    std::uint64_t strings_offset = 0;
    if (!checked_mul_u64(count, word_size, offsets_size) ||
        !checked_add_u64(word_size, offsets_size, strings_offset) || strings_offset > data.size()) {
        return workspace_result_t<void>::failure(
            coff_error("COFF archive linker offsets are truncated", phase));
    }
    std::size_t string_cursor = static_cast<std::size_t>(strings_offset);
    for (std::uint64_t index = 0; index < count; ++index) {
        auto stopped = context.poll();
        if (!stopped)
            return stopped;
        const auto offset_index = static_cast<std::size_t>(word_size + index * word_size);
        const auto member_offset = sixty_four ? read_u64_be(data.data() + offset_index)
                                               : read_u32_be(data.data() + offset_index);
        auto name = archive_table_string(data, string_cursor, context, phase);
        if (!name)
            return workspace_result_t<void>::failure(std::move(name.error()));
        auto appended = append_archive_symbol(name.value(), member_offset, table, member_by_offset,
                                              output, context, phase);
        if (!appended)
            return appended;
    }
    if (string_cursor != data.size())
        return workspace_result_t<void>::failure(
            coff_error("COFF archive linker member has trailing bytes", phase));
    return workspace_result_t<void>::success();
}

workspace_result_t<void> parse_second_linker_member(
    const std::vector<std::uint8_t>& data, const std::map<std::uint64_t, std::uint32_t>& member_by_offset,
    std::vector<coff_archive_symbol_t>& output, parse_context_t& context) {
    const char* phase = "coff_archive_linker";
    if (data.size() < 8)
        return workspace_result_t<void>::failure(
            coff_error("COFF archive second linker member is truncated", phase));
    std::size_t cursor = 0;
    const auto member_count = read_u32_le(data.data());
    cursor += 4;
    if (member_count > context.limits().max_archive_members)
        return workspace_result_t<void>::failure(coff_limit_error(
            "COFF archive second linker member count exceeds its configured limit", phase, member_count,
            context.limits().max_archive_members));
    std::uint64_t member_offsets_size = 0;
    std::uint64_t after_member_offsets = 0;
    if (!checked_mul_u64(member_count, 4, member_offsets_size) ||
        !checked_add_u64(cursor, member_offsets_size, after_member_offsets) ||
        after_member_offsets + 4 > data.size()) {
        return workspace_result_t<void>::failure(
            coff_error("COFF archive second linker member offsets are truncated", phase));
    }
    std::vector<std::uint32_t> member_indices;
    member_indices.reserve(member_count);
    for (std::uint32_t index = 0; index < member_count; ++index) {
        const auto member_offset = read_u32_le(data.data() + cursor + index * 4);
        const auto found = member_by_offset.find(member_offset);
        if (found == member_by_offset.end())
            return workspace_result_t<void>::failure(
                coff_error("COFF archive second linker member points outside the member table", phase,
                           member_offset));
        member_indices.push_back(found->second);
    }
    cursor = static_cast<std::size_t>(after_member_offsets);
    const auto symbol_count = read_u32_le(data.data() + cursor);
    cursor += 4;
    if (symbol_count > context.limits().max_archive_symbols)
        return workspace_result_t<void>::failure(coff_limit_error(
            "COFF archive second linker symbol count exceeds its configured limit", phase, symbol_count,
            context.limits().max_archive_symbols));
    std::uint64_t indices_size = 0;
    std::uint64_t strings_offset = 0;
    if (!checked_mul_u64(symbol_count, 2, indices_size) ||
        !checked_add_u64(cursor, indices_size, strings_offset) || strings_offset > data.size()) {
        return workspace_result_t<void>::failure(
            coff_error("COFF archive second linker symbol indices are truncated", phase));
    }
    const auto symbol_indices_offset = cursor;
    cursor = static_cast<std::size_t>(strings_offset);
    for (std::uint32_t index = 0; index < symbol_count; ++index) {
        auto stopped = context.poll();
        if (!stopped)
            return stopped;
        const auto source_index = read_u16_le(data.data() + symbol_indices_offset + index * 2);
        if (source_index == 0 || source_index > member_indices.size())
            return workspace_result_t<void>::failure(
                coff_error("COFF archive second linker symbol member index is invalid", phase));
        auto name = archive_table_string(data, cursor, context, phase);
        if (!name)
            return workspace_result_t<void>::failure(std::move(name.error()));
        const auto member_index = member_indices[source_index - 1];
        auto member_offset = member_by_offset.begin();
        for (; member_offset != member_by_offset.end(); ++member_offset)
            if (member_offset->second == member_index)
                break;
        if (member_offset == member_by_offset.end())
            return workspace_result_t<void>::failure(
                coff_error("COFF archive second linker member mapping is invalid", phase));
        auto appended = append_archive_symbol(name.value(), member_offset->first,
                                              coff_archive_symbol_table_t::second_linker_member,
                                              member_by_offset, output, context, phase);
        if (!appended)
            return appended;
    }
    if (cursor != data.size())
        return workspace_result_t<void>::failure(
            coff_error("COFF archive second linker member has trailing bytes", phase));
    return workspace_result_t<void>::success();
}

workspace_result_t<workspace_image_t> normalize_archive(
    const coff_image_t& archive, const byte_provider_t& provider, std::uint16_t machine,
    const cancellation_token_t& cancel) {
    workspace_image_t output;
    output.format = format_id_t::archive;
    output.architecture = coff_machine_to_architecture(machine);
    output.architecture_mode = coff_machine_to_mode(machine);
    output.abi = coff_machine_to_abi(machine);
    output.endian = endian_t::little;
    output.address_width_bits = output.architecture == architecture_id_t::x86 ||
                                        output.architecture == architecture_id_t::arm ||
                                        output.architecture == architecture_id_t::mips ||
                                        output.architecture == architecture_id_t::ppc ||
                                        output.architecture == architecture_id_t::riscv32
                                    ? 32 : 64;
    output.image_size = provider.size();
    output.header_size = archive_magic.size();
    output.format_name = "coff_archive";
    output.provider_size = provider.size();
    output.member = provider.member_metadata();
    image_section_t section;
    section.name = "archive";
    section.virtual_size = provider.size();
    section.file_size = provider.size();
    section.permissions = image_permission_read;
    output.sections.push_back(section);
    image_segment_t segment;
    segment.name = "archive";
    segment.virtual_size = provider.size();
    segment.file_size = provider.size();
    segment.permissions = image_permission_read;
    output.segments.push_back(segment);
    image_address_mapping_t mapping;
    mapping.size = provider.size();
    mapping.permissions = image_permission_read;
    output.address_mappings.push_back(mapping);
    std::vector<coff_archive_symbol_t> symbols = archive.archive_symbols;
    std::sort(symbols.begin(), symbols.end(), [](const auto& left, const auto& right) {
        return std::tie(left.name, left.member_header_offset, left.table) <
               std::tie(right.name, right.member_header_offset, right.table);
    });
    symbols.erase(std::unique(symbols.begin(), symbols.end(), [](const auto& left, const auto& right) {
        return left.name == right.name && left.member_header_offset == right.member_header_offset &&
               left.table == right.table;
    }), symbols.end());
    std::uint64_t ordinal = 0;
    for (const auto& source : symbols) {
        if (cancel.stop_requested())
            return workspace_result_t<workspace_image_t>::failure(coff_stop_error(cancel));
        image_symbol_t symbol;
        symbol.ordinal = ordinal++;
        symbol.name = source.name;
        symbol.address = make_address(source.member_header_offset, machine);
        symbol.kind = image_symbol_kind_t::metadata;
        symbol.binding = image_symbol_binding_t::global;
        output.symbols.push_back(std::move(symbol));
    }
    for (const auto& imported : archive.import_objects) {
        if (cancel.stop_requested())
            return workspace_result_t<workspace_image_t>::failure(coff_stop_error(cancel));
        image_import_t import;
        import.library = imported.library_name;
        import.name = imported.symbol_name;
        import.lookup_address = make_address(imported.file_offset, machine);
        import.address = make_address(imported.file_offset, machine);
        output.imports.push_back(import);
        image_symbol_t symbol;
        symbol.ordinal = ordinal++;
        symbol.name = imported.library_name;
        symbol.name.push_back('!');
        if (imported.symbol_name)
            symbol.name.append(*imported.symbol_name);
        else
            symbol.name.append("#").append(std::to_string(imported.ordinal_or_hint));
        symbol.address = import.address;
        symbol.kind = image_symbol_kind_t::import_symbol;
        symbol.binding = image_symbol_binding_t::external;
        output.symbols.push_back(std::move(symbol));
    }
    auto validation = validate_workspace_image(output, {}, false, cancel);
    if (!validation)
        return workspace_result_t<workspace_image_t>::failure(std::move(validation.error()));
    return workspace_result_t<workspace_image_t>::success(std::move(output));
}

workspace_result_t<coff_image_t> parse_archive(const byte_provider_t& provider,
                                               parse_context_t& context) {
    bounded_reader_t reader(provider, 0, provider.size(), context);
    std::array<std::uint8_t, archive_magic.size()> magic{};
    auto magic_read = reader.read(0, magic.data(), magic.size(), "coff_archive");
    if (!magic_read)
        return workspace_result_t<coff_image_t>::failure(std::move(magic_read.error()));
    if (magic != archive_magic)
        return workspace_result_t<coff_image_t>::failure(
            coff_error("COFF archive magic is invalid", "coff_archive", 0, archive_magic.size()));
    coff_image_t archive;
    archive.artifact_kind = coff_artifact_kind_t::archive;
    archive.header_size = archive_magic.size();
    std::vector<archive_member_raw_t> members;
    std::uint64_t cursor = archive_magic.size();
    std::uint32_t member_index = 0;
    while (cursor < provider.size()) {
        auto stopped = context.poll();
        if (!stopped)
            return workspace_result_t<coff_image_t>::failure(std::move(stopped.error()));
        if (member_index >= context.limits().max_archive_members)
            return workspace_result_t<coff_image_t>::failure(coff_limit_error(
                "COFF archive member count exceeds its configured limit", "coff_archive", member_index + 1,
                context.limits().max_archive_members));
        auto header_span = validate_span(cursor, sizeof(coff_archive_member_header_t), provider.size(),
                                         "coff_archive");
        if (!header_span)
            return workspace_result_t<coff_image_t>::failure(std::move(header_span.error()));
        std::array<std::uint8_t, sizeof(coff_archive_member_header_t)> bytes{};
        auto header_read = reader.read(cursor, bytes.data(), bytes.size(), "coff_archive");
        if (!header_read)
            return workspace_result_t<coff_image_t>::failure(std::move(header_read.error()));
        if (bytes[58] != static_cast<std::uint8_t>('`') ||
            bytes[59] != static_cast<std::uint8_t>('\n')) {
            return workspace_result_t<coff_image_t>::failure(
                coff_error("COFF archive member header terminator is invalid", "coff_archive", cursor, 60));
        }
        auto name = archive_header_name(bytes.data(), context, cursor);
        if (!name)
            return workspace_result_t<coff_image_t>::failure(std::move(name.error()));
        auto timestamp = parse_decimal(bytes.data() + 16, 12, true, "coff_archive", cursor + 16);
        auto uid = parse_decimal(bytes.data() + 28, 6, true, "coff_archive", cursor + 28);
        auto gid = parse_decimal(bytes.data() + 34, 6, true, "coff_archive", cursor + 34);
        auto mode = parse_decimal(bytes.data() + 40, 8, true, "coff_archive", cursor + 40);
        auto size = parse_decimal(bytes.data() + 48, 10, false, "coff_archive", cursor + 48);
        if (!timestamp || !uid || !gid || !mode || !size) {
            const auto& error = !timestamp ? timestamp.error() : !uid ? uid.error() : !gid ? gid.error()
                                             : !mode ? mode.error() : size.error();
            return workspace_result_t<coff_image_t>::failure(error);
        }
        if (size.value() > context.limits().max_member_size)
            return workspace_result_t<coff_image_t>::failure(coff_limit_error(
                "COFF archive member size exceeds its configured limit", "coff_archive", size.value(),
                context.limits().max_member_size));
        std::uint64_t data_offset = 0;
        std::uint64_t member_end = 0;
        if (!checked_add_u64(cursor, sizeof(coff_archive_member_header_t), data_offset) ||
            !checked_add_u64(data_offset, size.value(), member_end)) {
            return workspace_result_t<coff_image_t>::failure(
                coff_error("COFF archive member range overflows", "coff_archive", cursor));
        }
        auto member_span = validate_span(data_offset, size.value(), provider.size(), "coff_archive");
        if (!member_span)
            return workspace_result_t<coff_image_t>::failure(std::move(member_span.error()));
        archive_member_raw_t raw;
        raw.member.index = member_index;
        raw.member.name = name.take_value();
        raw.member.header_offset = cursor;
        raw.member.data_offset = data_offset;
        raw.member.size = size.value();
        raw.member.payload_offset = data_offset;
        raw.member.payload_size = size.value();
        raw.member.timestamp = timestamp.value();
        raw.member.uid = uid.value();
        raw.member.gid = gid.value();
        raw.member.mode = mode.value();
        raw.raw_name = raw.member.name;
        if (raw.raw_name.size() > 1 && raw.raw_name[0] == '/' &&
            std::all_of(raw.raw_name.begin() + 1, raw.raw_name.end(),
                        [](char value) { return value >= '0' && value <= '9'; })) {
            auto offset = parse_decimal_text(std::string_view(raw.raw_name).substr(1), "coff_archive");
            if (!offset)
                return workspace_result_t<coff_image_t>::failure(std::move(offset.error()));
            raw.is_long_name_reference = true;
            raw.long_name_offset = offset.value();
        } else if (raw.raw_name.rfind("#1/", 0) == 0) {
            auto length = parse_decimal_text(std::string_view(raw.raw_name).substr(3), "coff_archive");
            if (!length)
                return workspace_result_t<coff_image_t>::failure(std::move(length.error()));
            if (length.value() >= raw.member.size)
                return workspace_result_t<coff_image_t>::failure(
                    coff_error("COFF archive BSD member name consumes its payload", "coff_archive",
                               cursor, raw.member.size));
            raw.is_bsd_name = true;
            raw.bsd_name_size = length.value();
        }
        members.push_back(std::move(raw));
        cursor = member_end;
        if ((size.value() & 1u) != 0) {
            if (cursor >= provider.size())
                return workspace_result_t<coff_image_t>::failure(
                    coff_error("COFF archive odd-size member lacks padding", "coff_archive", cursor, 1));
            std::uint8_t padding = 0;
            auto padding_read = reader.read(cursor, &padding, 1, "coff_archive");
            if (!padding_read)
                return workspace_result_t<coff_image_t>::failure(std::move(padding_read.error()));
            if (padding != static_cast<std::uint8_t>('\n'))
                return workspace_result_t<coff_image_t>::failure(
                    coff_error("COFF archive odd-size member padding is invalid", "coff_archive", cursor, 1));
            ++cursor;
        }
        ++member_index;
    }
    if (members.empty())
        return workspace_result_t<coff_image_t>::failure(
            coff_error("COFF archive has no members", "coff_archive"));
    std::optional<std::vector<std::uint8_t>> long_names;
    std::uint32_t long_name_member_count = 0;
    for (const auto& raw : members) {
        if (raw.raw_name == "//") {
            ++long_name_member_count;
            if (long_name_member_count != 1)
                return workspace_result_t<coff_image_t>::failure(
                    coff_error("COFF archive has multiple long-name tables", "coff_archive",
                               raw.member.header_offset));
            bounded_reader_t name_reader(provider, raw.member.data_offset, raw.member.size, context);
            auto names = name_reader.vector(0, raw.member.size,
                                            context.limits().max_string_table_bytes, "coff_archive");
            if (!names)
                return workspace_result_t<coff_image_t>::failure(std::move(names.error()));
            long_names = names.take_value();
        }
    }
    std::uint32_t slash_members = 0;
    for (auto& raw : members) {
        if (raw.raw_name == "/") {
            raw.member.kind = coff_archive_member_kind_t::linker_member;
            ++slash_members;
            if (slash_members > 2)
                return workspace_result_t<coff_image_t>::failure(
                    coff_error("COFF archive has too many linker members", "coff_archive",
                               raw.member.header_offset));
        } else if (raw.raw_name == "/SYM64/") {
            raw.member.kind = coff_archive_member_kind_t::linker_member;
        } else if (raw.raw_name == "//") {
            raw.member.kind = coff_archive_member_kind_t::long_name_table;
            archive.archive_has_long_name_table = true;
        } else if (raw.is_long_name_reference) {
            if (!long_names)
                return workspace_result_t<coff_image_t>::failure(
                    coff_error("COFF archive long-name reference has no long-name table", "coff_archive",
                               raw.member.header_offset));
            auto name = resolve_long_archive_name(*long_names, raw.long_name_offset, context);
            if (!name)
                return workspace_result_t<coff_image_t>::failure(std::move(name.error()));
            raw.member.name = name.take_value();
        } else if (raw.is_bsd_name) {
            bounded_reader_t name_reader(provider, raw.member.data_offset, raw.member.size, context);
            auto name = parse_bsd_member_name(name_reader, raw.bsd_name_size, context);
            if (!name)
                return workspace_result_t<coff_image_t>::failure(std::move(name.error()));
            raw.member.name = name.take_value();
            if (!checked_add_u64(raw.member.data_offset, raw.bsd_name_size, raw.member.payload_offset) ||
                !checked_sub_u64(raw.member.size, raw.bsd_name_size, raw.member.payload_size)) {
                return workspace_result_t<coff_image_t>::failure(
                    coff_error("COFF archive BSD member payload range overflows", "coff_archive",
                               raw.member.header_offset));
            }
        } else {
            if (!raw.member.name.empty() && raw.member.name.back() == '/')
                raw.member.name.pop_back();
            if (raw.member.name.empty())
                return workspace_result_t<coff_image_t>::failure(
                    coff_error("COFF archive member name is empty", "coff_archive",
                               raw.member.header_offset));
        }
    }
    std::map<std::uint64_t, std::uint32_t> member_by_offset;
    for (const auto& raw : members)
        member_by_offset.emplace(raw.member.header_offset, raw.member.index);
    for (const auto& raw : members) {
        if (raw.member.kind != coff_archive_member_kind_t::linker_member)
            continue;
        bounded_reader_t linker_reader(provider, raw.member.data_offset, raw.member.size, context);
        auto data = linker_reader.vector(0, raw.member.size,
                                         context.limits().max_string_table_bytes, "coff_archive_linker");
        if (!data)
            return workspace_result_t<coff_image_t>::failure(std::move(data.error()));
        workspace_result_t<void> parsed = workspace_result_t<void>::success();
        if (raw.raw_name == "/") {
            if (!archive.archive_has_first_linker_member) {
                archive.archive_has_first_linker_member = true;
                parsed = parse_first_linker_member(data.value(), member_by_offset,
                                                   archive.archive_symbols, context,
                                                   coff_archive_symbol_table_t::first_linker_member, false);
            } else {
                archive.archive_has_second_linker_member = true;
                parsed = parse_second_linker_member(data.value(), member_by_offset,
                                                    archive.archive_symbols, context);
            }
        } else {
            if (archive.archive_has_64bit_symbol_table)
                return workspace_result_t<coff_image_t>::failure(
                    coff_error("COFF archive has multiple 64-bit symbol tables", "coff_archive",
                               raw.member.header_offset));
            archive.archive_has_64bit_symbol_table = true;
            parsed = parse_first_linker_member(data.value(), member_by_offset,
                                               archive.archive_symbols, context,
                                               coff_archive_symbol_table_t::symbol_table_64, true);
        }
        if (!parsed)
            return workspace_result_t<coff_image_t>::failure(std::move(parsed.error()));
    }
    const bool scan_member_symbols = !archive.archive_has_first_linker_member &&
                                     !archive.archive_has_second_linker_member &&
                                     !archive.archive_has_64bit_symbol_table;
    std::optional<std::uint16_t> selected_machine;
    for (auto& raw : members) {
        if (raw.member.kind == coff_archive_member_kind_t::linker_member ||
            raw.member.kind == coff_archive_member_kind_t::long_name_table)
            continue;
        if (raw.member.payload_size < 4)
            return workspace_result_t<coff_image_t>::failure(
                coff_error("COFF archive payload is too small for an object", "coff_archive",
                           raw.member.payload_offset, raw.member.payload_size));
        bounded_reader_t member_reader(provider, raw.member.payload_offset, raw.member.payload_size,
                                       context);
        std::array<std::uint8_t, 4> probe{};
        auto probe_read = member_reader.read(0, probe.data(), probe.size(), "coff_archive");
        if (!probe_read)
            return workspace_result_t<coff_image_t>::failure(std::move(probe_read.error()));
        if (read_u16_le(probe.data()) == 0 && read_u16_le(probe.data() + 2) == 0xffffu) {
            auto imported = parse_import_object(member_reader, context);
            if (!imported)
                return workspace_result_t<coff_image_t>::failure(std::move(imported.error()));
            auto value = imported.take_value();
            value.file_offset = raw.member.payload_offset;
            value.size = raw.member.payload_size;
            raw.member.kind = coff_archive_member_kind_t::import_object;
            raw.member.machine = value.machine;
            archive.import_objects.push_back(value);
            if (!selected_machine)
                selected_machine = value.machine;
            else if (*selected_machine != value.machine)
                archive.archive_has_mixed_machines = true;
        } else {
            auto object = parse_object(member_reader, context);
            if (!object)
                return workspace_result_t<coff_image_t>::failure(std::move(object.error()));
            auto value = object.take_value();
            raw.member.kind = coff_archive_member_kind_t::object;
            raw.member.machine = value.machine;
            raw.member.section_count = static_cast<std::uint32_t>(value.sections.size());
            raw.member.symbol_count = static_cast<std::uint32_t>(value.symbols.size());
            raw.member.relocation_count = static_cast<std::uint32_t>(value.relocations.size());
            if (!selected_machine)
                selected_machine = value.machine;
            else if (*selected_machine != value.machine)
                archive.archive_has_mixed_machines = true;
            if (scan_member_symbols) {
                for (const auto& symbol : value.symbols) {
                    if (!symbol.is_external || !symbol.is_defined || symbol.name.empty())
                        continue;
                    auto appended = append_archive_symbol(
                        symbol.name, raw.member.header_offset,
                        coff_archive_symbol_table_t::member_scan, member_by_offset,
                        archive.archive_symbols, context, "coff_archive");
                    if (!appended)
                        return workspace_result_t<coff_image_t>::failure(std::move(appended.error()));
                }
            }
        }
    }
    for (const auto& symbol : archive.archive_symbols) {
        if (symbol.member_index >= members.size() ||
            (members[symbol.member_index].member.kind != coff_archive_member_kind_t::object &&
             members[symbol.member_index].member.kind != coff_archive_member_kind_t::import_object)) {
            return workspace_result_t<coff_image_t>::failure(
                coff_error("COFF archive linker symbol points to a non-object member", "coff_archive_linker",
                           symbol.member_header_offset));
        }
    }
    if (!selected_machine)
        return workspace_result_t<coff_image_t>::failure(make_workspace_error(
            workspace_error_code_t::unsupported_format,
            "COFF archive contains no supported object members", "coff_archive"));
    archive.machine = *selected_machine;
    for (auto& raw : members)
        archive.archive_members.push_back(std::move(raw.member));
    auto normalized = normalize_archive(archive, provider, archive.machine, context.cancel());
    if (!normalized)
        return workspace_result_t<coff_image_t>::failure(std::move(normalized.error()));
    archive.normalized = normalized.take_value();
    return workspace_result_t<coff_image_t>::success(std::move(archive));
}

workspace_result_t<coff_image_t> parse_non_archive(const byte_provider_t& provider,
                                                    parse_context_t& context) {
    bounded_reader_t reader(provider, 0, provider.size(), context);
    if (provider.size() < 4)
        return workspace_result_t<coff_image_t>::failure(
            coff_error("COFF input is too small", "coff_probe", 0, 4));
    std::array<std::uint8_t, 4> probe{};
    auto probe_read = reader.read(0, probe.data(), probe.size(), "coff_probe");
    if (!probe_read)
        return workspace_result_t<coff_image_t>::failure(std::move(probe_read.error()));
    if (read_u16_le(probe.data()) == 0 && read_u16_le(probe.data() + 2) == 0xffffu) {
        auto import = parse_import_object(reader, context);
        if (!import)
            return workspace_result_t<coff_image_t>::failure(std::move(import.error()));
        auto value = import.take_value();
        value.file_offset = 0;
        coff_image_t image;
        image.artifact_kind = coff_artifact_kind_t::import_object;
        image.machine = value.machine;
        image.time_date_stamp = value.time_date_stamp;
        image.header_size = sizeof(coff_import_object_header_t);
        image.import_objects.push_back(value);
        auto normalized = normalize_import(value, provider, context.cancel());
        if (!normalized)
            return workspace_result_t<coff_image_t>::failure(std::move(normalized.error()));
        image.normalized = normalized.take_value();
        return workspace_result_t<coff_image_t>::success(std::move(image));
    }
    auto record = parse_object(reader, context);
    if (!record)
        return workspace_result_t<coff_image_t>::failure(std::move(record.error()));
    auto value = record.take_value();
    coff_image_t image;
    image.artifact_kind = coff_artifact_kind_t::object;
    image.machine = value.machine;
    image.characteristics = value.characteristics;
    image.time_date_stamp = value.time_date_stamp;
    image.symbol_table_offset = value.symbol_table_offset;
    image.symbol_table_count = value.symbol_table_count;
    image.header_size = value.header_size;
    image.sections = std::move(value.sections);
    image.symbols = std::move(value.symbols);
    image.relocations = std::move(value.relocations);
    object_record_t normalized_record;
    normalized_record.machine = image.machine;
    normalized_record.characteristics = image.characteristics;
    normalized_record.time_date_stamp = image.time_date_stamp;
    normalized_record.symbol_table_offset = image.symbol_table_offset;
    normalized_record.symbol_table_count = image.symbol_table_count;
    normalized_record.header_size = image.header_size;
    normalized_record.sections = image.sections;
    normalized_record.symbols = image.symbols;
    normalized_record.relocations = image.relocations;
    normalized_record.synthetic_image_size = image.header_size;
    for (const auto& section : image.sections) {
        if (section.raw_size == 0)
            continue;
        std::uint64_t end = 0;
        if (!checked_add_u64(section.normalized_virtual_address, section.raw_size, end))
            return workspace_result_t<coff_image_t>::failure(
                coff_error("COFF synthetic section extent overflows", "coff_normalize"));
        if (end > normalized_record.synthetic_image_size)
            normalized_record.synthetic_image_size = end;
    }
    auto normalized = normalize_object(normalized_record, provider, context.cancel());
    if (!normalized)
        return workspace_result_t<coff_image_t>::failure(std::move(normalized.error()));
    image.normalized = normalized.take_value();
    return workspace_result_t<coff_image_t>::success(std::move(image));
}

} 

architecture_id_t coff_machine_to_architecture(std::uint16_t machine) noexcept {
    switch (machine) {
        case coff_machine_i386: return architecture_id_t::x86;
        case coff_machine_amd64: return architecture_id_t::x86_64;
        case coff_machine_arm:
        case coff_machine_armnt: return architecture_id_t::arm;
        case coff_machine_arm64: return architecture_id_t::aarch64;
        case coff_machine_arm64ec: return architecture_id_t::arm64ec;
        case coff_machine_mips16:
        case coff_machine_mipsfpu:
        case coff_machine_mipsfpu16: return architecture_id_t::mips;
        case coff_machine_powerpc:
        case coff_machine_powerpcfp: return architecture_id_t::ppc;
        case coff_machine_riscv32: return architecture_id_t::riscv32;
        case coff_machine_riscv64: return architecture_id_t::riscv64;
        default: return architecture_id_t::unknown;
    }
}

architecture_mode_t coff_machine_to_mode(std::uint16_t machine) noexcept {
    switch (machine) {
        case coff_machine_i386: return architecture_mode_t::x86_32;
        case coff_machine_amd64: return architecture_mode_t::x86_64;
        case coff_machine_arm:
        case coff_machine_armnt: return architecture_mode_t::arm_a32;
        case coff_machine_arm64:
        case coff_machine_arm64ec: return architecture_mode_t::aarch64;
        case coff_machine_mips16:
        case coff_machine_mipsfpu:
        case coff_machine_mipsfpu16: return architecture_mode_t::mips32;
        case coff_machine_powerpc:
        case coff_machine_powerpcfp: return architecture_mode_t::ppc32;
        case coff_machine_riscv32: return architecture_mode_t::riscv32;
        case coff_machine_riscv64: return architecture_mode_t::riscv64;
        default: return architecture_mode_t::unknown;
    }
}

abi_id_t coff_machine_to_abi(std::uint16_t machine) noexcept {
    switch (machine) {
        case coff_machine_i386: return abi_id_t::windows_x86;
        case coff_machine_amd64: return abi_id_t::windows_x64;
        case coff_machine_arm:
        case coff_machine_armnt:
        case coff_machine_arm64: return abi_id_t::windows_arm64;
        case coff_machine_arm64ec: return abi_id_t::windows_arm64ec;
        case coff_machine_mips16:
        case coff_machine_mipsfpu:
        case coff_machine_mipsfpu16:
        case coff_machine_powerpc:
        case coff_machine_powerpcfp:
        case coff_machine_riscv32:
        case coff_machine_riscv64: return abi_id_t::sysv;
        default: return abi_id_t::unknown;
    }
}

const char* coff_machine_name(std::uint16_t machine) noexcept {
    switch (machine) {
        case coff_machine_i386: return "i386";
        case coff_machine_amd64: return "amd64";
        case coff_machine_arm: return "arm";
        case coff_machine_armnt: return "armnt";
        case coff_machine_arm64: return "arm64";
        case coff_machine_arm64ec: return "arm64ec";
        case coff_machine_mips16: return "mips16";
        case coff_machine_mipsfpu: return "mipsfpu";
        case coff_machine_mipsfpu16: return "mipsfpu16";
        case coff_machine_powerpc: return "powerpc";
        case coff_machine_powerpcfp: return "powerpcfp";
        case coff_machine_riscv32: return "riscv32";
        case coff_machine_riscv64: return "riscv64";
        default: return "unknown";
    }
}

workspace_result_t<coff_image_t> parse_coff_image(
    const byte_provider_t& provider, const coff_parse_limits_t& limits,
    const cancellation_token_t& cancel) {
    try {
        if (cancel.stop_requested())
            return workspace_result_t<coff_image_t>::failure(coff_stop_error(cancel));
        if (provider.size() < 4)
            return workspace_result_t<coff_image_t>::failure(
                coff_error("COFF input is too small", "coff_probe", 0, 4));
        parse_context_t context(limits, cancel);
        if (provider.size() >= archive_magic.size()) {
            std::array<std::uint8_t, archive_magic.size()> probe{};
            auto read = provider.read_exact(0, probe.data(), probe.size(), cancel);
            if (!read)
                return workspace_result_t<coff_image_t>::failure(std::move(read.error()));
            if (probe == archive_magic)
                return parse_archive(provider, context);
        }
        return parse_non_archive(provider, context);
    } catch (const std::bad_alloc&) {
        return workspace_result_t<coff_image_t>::failure(coff_allocation_error());
    } catch (const std::length_error&) {
        return workspace_result_t<coff_image_t>::failure(coff_allocation_error());
    }
}

workspace_result_t<coff_image_t> parse_coff_image(const byte_provider_t& provider,
                                                   const cancellation_token_t& cancel) {
    return parse_coff_image(provider, coff_parse_limits_t{}, cancel);
}

workspace_result_t<workspace_image_t> parse_coff(
    const byte_provider_t& provider, const coff_parse_limits_t& limits,
    const cancellation_token_t& cancel) {
    auto image = parse_coff_image(provider, limits, cancel);
    if (!image)
        return workspace_result_t<workspace_image_t>::failure(std::move(image.error()));
    return workspace_result_t<workspace_image_t>::success(std::move(image.value().normalized));
}

workspace_result_t<workspace_image_t> parse_coff(const byte_provider_t& provider,
                                                  const cancellation_token_t& cancel) {
    return parse_coff(provider, coff_parse_limits_t{}, cancel);
}

workspace_result_t<bool> is_coff_file(const byte_provider_t& provider,
                                      const cancellation_token_t& cancel) {
    if (cancel.stop_requested())
        return workspace_result_t<bool>::failure(coff_stop_error(cancel));
    if (provider.size() < 4)
        return workspace_result_t<bool>::success(false);
    std::array<std::uint8_t, 8> probe{};
    const auto size = (std::min)(provider.size(), static_cast<std::uint64_t>(probe.size()));
    auto read = provider.read_exact(0, probe.data(), size, cancel);
    if (!read)
        return workspace_result_t<bool>::failure(std::move(read.error()));
    if (size == archive_magic.size() && probe == archive_magic)
        return workspace_result_t<bool>::success(true);
    if (read_u16_le(probe.data()) == 0 && read_u16_le(probe.data() + 2) == 0xffffu)
        return workspace_result_t<bool>::success(true);
    return workspace_result_t<bool>::success(
        coff_machine_to_architecture(read_u16_le(probe.data())) != architecture_id_t::unknown);
}

}
