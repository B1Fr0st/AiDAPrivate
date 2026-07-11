#include "dex_image.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <new>
#include <unordered_map>
#include <unordered_set>

namespace aida::analysis {
namespace {

constexpr std::uint32_t kDexHeaderSize = 112;
constexpr std::uint32_t kDexEndianConstant = 0x12345678U;
constexpr std::uint32_t kNoIndex = 0xffffffffU;
constexpr std::uint16_t kMapHeaderItem = 0x0000U;
constexpr std::uint16_t kMapStringIdItem = 0x0001U;
constexpr std::uint16_t kMapTypeIdItem = 0x0002U;
constexpr std::uint16_t kMapProtoIdItem = 0x0003U;
constexpr std::uint16_t kMapFieldIdItem = 0x0004U;
constexpr std::uint16_t kMapMethodIdItem = 0x0005U;
constexpr std::uint16_t kMapClassDefItem = 0x0006U;
constexpr std::uint16_t kMapMapList = 0x1000U;
constexpr std::uint16_t kMapTypeList = 0x1001U;
constexpr std::uint16_t kMapClassDataItem = 0x2000U;
constexpr std::uint16_t kMapCodeItem = 0x2001U;
constexpr std::uint16_t kMapStringDataItem = 0x2002U;
constexpr std::uint16_t kMapDebugInfoItem = 0x2003U;
constexpr std::uint8_t kDebugEndSequence = 0x00U;
constexpr std::uint8_t kDebugAdvancePc = 0x01U;
constexpr std::uint8_t kDebugAdvanceLine = 0x02U;
constexpr std::uint8_t kDebugStartLocal = 0x03U;
constexpr std::uint8_t kDebugStartLocalExtended = 0x04U;
constexpr std::uint8_t kDebugEndLocal = 0x05U;
constexpr std::uint8_t kDebugRestartLocal = 0x06U;
constexpr std::uint8_t kDebugSetPrologueEnd = 0x07U;
constexpr std::uint8_t kDebugSetEpilogueBegin = 0x08U;
constexpr std::uint8_t kDebugSetFile = 0x09U;
constexpr std::uint8_t kDebugFirstSpecial = 0x0aU;
constexpr std::int32_t kDebugLineBase = -4;
constexpr std::uint8_t kDebugLineRange = 15U;

workspace_error_t dex_error(workspace_error_code_t code, std::string message,
                            std::string phase, std::optional<std::uint64_t> offset = {},
                            std::optional<std::uint64_t> size = {}) {
    auto error = make_workspace_error(code, std::move(message), std::move(phase));
    error.offset = offset;
    error.size = size;
    return error;
}

workspace_error_t dex_stop_error(const cancellation_token_t& cancel, std::string phase) {
    auto error = dex_error(cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                                      : workspace_error_code_t::cancelled,
                           "DEX parsing cancelled", std::move(phase));
    error.deadline = cancel.deadline_exceeded();
    error.cancellation = !error.deadline;
    return error;
}

bool span_within(std::uint64_t offset, std::uint64_t size, std::uint64_t limit) noexcept {
    return offset <= limit && size <= limit - offset;
}

bool add_u32(std::uint32_t lhs, std::uint32_t rhs, std::uint32_t& value) noexcept {
    if (rhs > (std::numeric_limits<std::uint32_t>::max)() - lhs)
        return false;
    value = lhs + rhs;
    return true;
}

std::uint16_t read_u16_le(const std::uint8_t* value) noexcept {
    return static_cast<std::uint16_t>(value[0]) |
           (static_cast<std::uint16_t>(value[1]) << 8U);
}

std::uint32_t read_u32_le(const std::uint8_t* value) noexcept {
    return static_cast<std::uint32_t>(value[0]) |
           (static_cast<std::uint32_t>(value[1]) << 8U) |
           (static_cast<std::uint32_t>(value[2]) << 16U) |
           (static_cast<std::uint32_t>(value[3]) << 24U);
}

std::int32_t sign_extend(std::uint32_t value, unsigned bits) noexcept {
    const auto shift = 32U - bits;
    return static_cast<std::int32_t>(value << shift) >> shift;
}

bool is_decimal_version(const std::uint8_t* bytes) noexcept {
    return bytes[0] >= '0' && bytes[0] <= '9' &&
           bytes[1] >= '0' && bytes[1] <= '9' &&
           bytes[2] >= '0' && bytes[2] <= '9' && bytes[3] == 0;
}

std::string make_version(const std::uint8_t* bytes, std::size_t count) {
    std::string value;
    value.reserve(count);
    for (std::size_t index = 0; index < count && bytes[index] != 0; ++index)
        value.push_back(static_cast<char>(bytes[index]));
    return value;
}

bool is_dex_magic(const std::uint8_t* data, std::size_t size) noexcept {
    return size >= 8 && data[0] == 'd' && data[1] == 'e' && data[2] == 'x' && data[3] == '\n' &&
           is_decimal_version(data + 4);
}

bool is_compact_dex_magic(const std::uint8_t* data, std::size_t size) noexcept {
    return size >= 8 && data[0] == 'c' && data[1] == 'd' && data[2] == 'e' && data[3] == 'x' &&
           is_decimal_version(data + 4);
}

std::optional<std::uint64_t> fixed_map_item_size(std::uint16_t type) noexcept {
    switch (type) {
        case kMapHeaderItem:
            return kDexHeaderSize;
        case kMapStringIdItem:
        case kMapTypeIdItem:
            return 4;
        case kMapProtoIdItem:
            return 12;
        case kMapFieldIdItem:
        case kMapMethodIdItem:
            return 8;
        case kMapClassDefItem:
            return 32;
        default:
            return std::nullopt;
    }
}

bool is_index_reference_opcode(std::uint8_t opcode, dalvik_reference_kind_t& kind) noexcept {
    if (opcode == 0x1aU || opcode == 0x1bU) {
        kind = dalvik_reference_kind_t::string;
        return true;
    }
    if (opcode == 0x1cU || opcode == 0x1fU || opcode == 0x20U || opcode == 0x22U ||
        opcode == 0x23U || opcode == 0x24U || opcode == 0x25U) {
        kind = dalvik_reference_kind_t::type;
        return true;
    }
    if ((opcode >= 0x52U && opcode <= 0x6dU) ||
        (opcode >= 0xd0U && opcode <= 0xe2U)) {
        kind = opcode <= 0x6dU ? dalvik_reference_kind_t::field
                               : dalvik_reference_kind_t::none;
        return kind != dalvik_reference_kind_t::none;
    }
    if ((opcode >= 0x6eU && opcode <= 0x78U) || opcode == 0xfaU || opcode == 0xfbU) {
        kind = dalvik_reference_kind_t::method;
        return true;
    }
    if (opcode == 0xfcU || opcode == 0xfdU) {
        kind = dalvik_reference_kind_t::call_site;
        return true;
    }
    if (opcode == 0xfeU) {
        kind = dalvik_reference_kind_t::method_handle;
        return true;
    }
    if (opcode == 0xffU) {
        kind = dalvik_reference_kind_t::proto;
        return true;
    }
    return false;
}

std::uint16_t dalvik_opcode_width(std::uint8_t opcode) noexcept {
    switch (opcode) {
        case 0x00U: case 0x01U: case 0x04U: case 0x07U: case 0x0aU: case 0x0bU:
        case 0x0cU: case 0x0dU: case 0x0eU: case 0x0fU: case 0x10U: case 0x11U:
        case 0x12U: case 0x1dU: case 0x1eU: case 0x21U: case 0x27U: case 0x28U:
            return 1;
        case 0x02U: case 0x05U: case 0x08U: case 0x13U: case 0x15U: case 0x16U:
        case 0x19U: case 0x1aU: case 0x1cU: case 0x1fU: case 0x20U: case 0x22U:
        case 0x29U: case 0x38U: case 0x39U: case 0x3aU: case 0x3bU: case 0x3cU:
        case 0x3dU: case 0xfeU: case 0xffU:
            return 2;
        case 0x03U: case 0x06U: case 0x09U: case 0x14U: case 0x17U: case 0x1bU:
        case 0x23U: case 0x24U: case 0x25U: case 0x26U: case 0x2aU: case 0x2bU:
        case 0x2cU: case 0xfcU: case 0xfdU:
            return 3;
        case 0x18U:
            return 5;
        case 0xfaU: case 0xfbU:
            return 4;
        default:
            break;
    }
    if ((opcode >= 0x2dU && opcode <= 0x37U) ||
        (opcode >= 0x44U && opcode <= 0x51U) ||
        (opcode >= 0x6eU && opcode <= 0x72U) ||
        (opcode >= 0x74U && opcode <= 0x78U))
        return 3;
    if ((opcode >= 0x52U && opcode <= 0x6dU) ||
        (opcode >= 0xd0U && opcode <= 0xe2U))
        return 2;
    if ((opcode >= 0x7bU && opcode <= 0x8fU) ||
        (opcode >= 0x90U && opcode <= 0xafU))
        return opcode <= 0x8fU ? 1 : 2;
    if (opcode >= 0xb0U && opcode <= 0xcfU)
        return 1;
    return 0;
}

class dex_parser_t {
public:
    dex_parser_t(const std::vector<std::uint8_t>& data, std::uint64_t provider_offset,
                 std::uint64_t provider_size, const byte_provider_identity_t& identity,
                 dex_container_info_t container, const dex_parse_limits_t& limits,
                 const cancellation_token_t& cancel)
        : data_(data), provider_offset_(provider_offset), provider_size_(provider_size),
          identity_(identity), container_(std::move(container)), limits_(limits), cancel_(cancel) {}

    workspace_result_t<dex_image_t> parse() {
        if (!poll("dex.header"))
            return workspace_result_t<dex_image_t>::failure(error_);
        if (!parse_header() || !parse_map() || !parse_strings() || !parse_types() ||
            !parse_protos() || !parse_fields() || !parse_methods() || !parse_classes() ||
            !build_normalized())
            return workspace_result_t<dex_image_t>::failure(error_);
        return workspace_result_t<dex_image_t>::success(std::move(image_));
    }

private:
    bool fail(workspace_error_code_t code, std::string message, std::string phase,
              std::optional<std::uint64_t> offset = {}, std::optional<std::uint64_t> size = {}) {
        if (!failed_) {
            if (offset)
                *offset += provider_offset_;
            error_ = dex_error(code, std::move(message), std::move(phase), offset, size);
            failed_ = true;
        }
        return false;
    }

    bool poll(const char* phase) {
        if (!cancel_.stop_requested())
            return true;
        if (!failed_) {
            error_ = dex_stop_error(cancel_, phase);
            failed_ = true;
        }
        return false;
    }

    bool require(std::uint64_t offset, std::uint64_t size, const char* phase) {
        if (!span_within(offset, size, data_.size()))
            return fail(workspace_error_code_t::out_of_range,
                        "DEX record extends beyond the declared file size", phase, offset, size);
        return true;
    }

    bool u16(std::uint64_t offset, std::uint16_t& value, const char* phase) {
        if (!require(offset, 2, phase))
            return false;
        value = read_u16_le(data_.data() + offset);
        return true;
    }

    bool u32(std::uint64_t offset, std::uint32_t& value, const char* phase) {
        if (!require(offset, 4, phase))
            return false;
        value = read_u32_le(data_.data() + offset);
        return true;
    }

    bool uleb(std::uint32_t& offset, std::uint32_t& value, const char* phase) {
        std::uint64_t accumulated = 0;
        for (std::uint32_t index = 0; index < 5; ++index) {
            if (!require(offset, 1, phase))
                return false;
            const auto byte = data_[offset++];
            accumulated |= static_cast<std::uint64_t>(byte & 0x7fU) << (index * 7U);
            if ((byte & 0x80U) == 0) {
                if (accumulated > (std::numeric_limits<std::uint32_t>::max)())
                    return fail(workspace_error_code_t::malformed_image,
                                "DEX ULEB128 value exceeds 32 bits", phase, offset - 1, 1);
                value = static_cast<std::uint32_t>(accumulated);
                return true;
            }
        }
        return fail(workspace_error_code_t::malformed_image,
                    "DEX ULEB128 sequence is unterminated", phase, offset - 5, 5);
    }

    bool sleb(std::uint32_t& offset, std::int32_t& value, const char* phase) {
        std::uint64_t accumulated = 0;
        std::uint8_t byte = 0;
        std::uint32_t count = 0;
        for (; count < 5; ++count) {
            if (!require(offset, 1, phase))
                return false;
            byte = data_[offset++];
            accumulated |= static_cast<std::uint64_t>(byte & 0x7fU) << (count * 7U);
            if ((byte & 0x80U) == 0)
                break;
        }
        if (count == 5)
            return fail(workspace_error_code_t::malformed_image,
                        "DEX SLEB128 sequence is unterminated", phase, offset - 5, 5);
        const auto bits = (count + 1U) * 7U;
        if (bits < 64U && (byte & 0x40U) != 0)
            accumulated |= (~0ULL) << bits;
        if (static_cast<std::int64_t>(accumulated) < (std::numeric_limits<std::int32_t>::min)() ||
            static_cast<std::int64_t>(accumulated) > (std::numeric_limits<std::int32_t>::max)())
            return fail(workspace_error_code_t::malformed_image,
                        "DEX SLEB128 value exceeds 32 bits", phase, offset - count - 1, count + 1);
        value = static_cast<std::int32_t>(accumulated);
        return true;
    }

    bool ulebp1(std::uint32_t& offset, std::optional<std::uint32_t>& value, const char* phase) {
        std::uint32_t encoded = 0;
        if (!uleb(offset, encoded, phase))
            return false;
        if (encoded == 0) {
            value.reset();
            return true;
        }
        value = encoded - 1U;
        return true;
    }

    bool count_within(std::uint32_t value, std::uint32_t limit, const char* name,
                      std::uint64_t offset) {
        if (value <= limit)
            return true;
        return fail(workspace_error_code_t::limit_exceeded,
                    std::string(name) + " exceeds parser limit", "dex.limits", offset, value);
    }

    bool table_range(std::uint32_t offset, std::uint32_t count, std::uint32_t element_size,
                     const char* phase) {
        if (count == 0)
            return offset == 0 || fail(workspace_error_code_t::malformed_image,
                                       "empty DEX table has a nonzero offset", phase, offset, 0);
        if ((offset & 3U) != 0)
            return fail(workspace_error_code_t::malformed_image,
                        "DEX identifier table is not four-byte aligned", phase, offset, 0);
        const auto size = static_cast<std::uint64_t>(count) * element_size;
        return require(offset, size, phase);
    }

    bool parse_header() {
        if (!require(0, kDexHeaderSize, "dex.header"))
            return false;
        if (!is_dex_magic(data_.data(), data_.size()))
            return fail(workspace_error_code_t::unsupported_format,
                        "input is not a standard DEX file", "dex.header", 0, 8);
        std::copy_n(data_.data(), image_.header.magic.size(), image_.header.magic.begin());
        if (!u32(8, image_.header.checksum, "dex.header") ||
            !require(12, image_.header.signature.size(), "dex.header"))
            return false;
        std::copy_n(data_.data() + 12, image_.header.signature.size(), image_.header.signature.begin());
        if (!u32(32, image_.header.file_size, "dex.header") ||
            !u32(36, image_.header.header_size, "dex.header") ||
            !u32(40, image_.header.endian_tag, "dex.header") ||
            !u32(44, image_.header.link_size, "dex.header") ||
            !u32(48, image_.header.link_offset, "dex.header") ||
            !u32(52, image_.header.map_offset, "dex.header") ||
            !u32(56, image_.header.string_ids_size, "dex.header") ||
            !u32(60, image_.header.string_ids_offset, "dex.header") ||
            !u32(64, image_.header.type_ids_size, "dex.header") ||
            !u32(68, image_.header.type_ids_offset, "dex.header") ||
            !u32(72, image_.header.proto_ids_size, "dex.header") ||
            !u32(76, image_.header.proto_ids_offset, "dex.header") ||
            !u32(80, image_.header.field_ids_size, "dex.header") ||
            !u32(84, image_.header.field_ids_offset, "dex.header") ||
            !u32(88, image_.header.method_ids_size, "dex.header") ||
            !u32(92, image_.header.method_ids_offset, "dex.header") ||
            !u32(96, image_.header.class_defs_size, "dex.header") ||
            !u32(100, image_.header.class_defs_offset, "dex.header") ||
            !u32(104, image_.header.data_size, "dex.header") ||
            !u32(108, image_.header.data_offset, "dex.header"))
            return false;
        if (image_.header.file_size != data_.size())
            return fail(workspace_error_code_t::malformed_image,
                        "DEX header file size does not match the bounded payload", "dex.header", 32, 4);
        if (image_.header.header_size != kDexHeaderSize)
            return fail(workspace_error_code_t::malformed_image,
                        "DEX header size is invalid", "dex.header", 36, 4);
        if (image_.header.endian_tag != kDexEndianConstant)
            return fail(workspace_error_code_t::unsupported_format,
                        "DEX reverse-endian payloads are unsupported", "dex.header", 40, 4);
        if (image_.header.map_offset == 0 || (image_.header.map_offset & 3U) != 0)
            return fail(workspace_error_code_t::malformed_image,
                        "DEX map offset is absent or misaligned", "dex.header", 52, 4);
        if (!table_range(image_.header.string_ids_offset, image_.header.string_ids_size, 4,
                         "dex.string_ids") ||
            !table_range(image_.header.type_ids_offset, image_.header.type_ids_size, 4,
                         "dex.type_ids") ||
            !table_range(image_.header.proto_ids_offset, image_.header.proto_ids_size, 12,
                         "dex.proto_ids") ||
            !table_range(image_.header.field_ids_offset, image_.header.field_ids_size, 8,
                         "dex.field_ids") ||
            !table_range(image_.header.method_ids_offset, image_.header.method_ids_size, 8,
                         "dex.method_ids") ||
            !table_range(image_.header.class_defs_offset, image_.header.class_defs_size, 32,
                         "dex.class_defs"))
            return false;
        if (!count_within(image_.header.string_ids_size, limits_.max_string_ids, "string id count", 56) ||
            !count_within(image_.header.type_ids_size, limits_.max_type_ids, "type id count", 64) ||
            !count_within(image_.header.proto_ids_size, limits_.max_proto_ids, "proto id count", 72) ||
            !count_within(image_.header.field_ids_size, limits_.max_field_ids, "field id count", 80) ||
            !count_within(image_.header.method_ids_size, limits_.max_method_ids, "method id count", 88) ||
            !count_within(image_.header.class_defs_size, limits_.max_class_defs, "class definition count", 96))
            return false;
        if (image_.header.link_size != 0 &&
            !require(image_.header.link_offset, image_.header.link_size, "dex.link"))
            return false;
        if (image_.header.data_size == 0 || (image_.header.data_offset & 3U) != 0 ||
            !require(image_.header.data_offset, image_.header.data_size, "dex.data"))
            return fail(workspace_error_code_t::malformed_image,
                        "DEX data section is invalid", "dex.header", 104, 8);
        image_.dex_offset = provider_offset_;
        image_.container = container_;
        image_.managed_identity.container_kind = container_.kind;
        image_.managed_identity.version = make_version(data_.data() + 4, 3);
        image_.managed_identity.dex_offset = provider_offset_;
        image_.managed_identity.dex_signature = image_.header.signature;
        image_.managed_identity.dex_checksum = image_.header.checksum;
        return true;
    }

    bool parse_map() {
        std::uint32_t item_count = 0;
        if (!u32(image_.header.map_offset, item_count, "dex.map"))
            return false;
        if (!count_within(item_count, limits_.max_map_items, "map item count", image_.header.map_offset))
            return false;
        const auto bytes = static_cast<std::uint64_t>(item_count) * 12U;
        if (!require(static_cast<std::uint64_t>(image_.header.map_offset) + 4U, bytes, "dex.map"))
            return false;
        image_.map_items.reserve(item_count);
        std::unordered_set<std::uint16_t> seen_types;
        std::unordered_map<std::uint16_t, dex_map_item_t> mapped_items;
        std::uint32_t previous_offset = 0;
        for (std::uint32_t index = 0; index < item_count; ++index) {
            if ((index & 255U) == 0 && !poll("dex.map"))
                return false;
            const std::uint64_t offset = static_cast<std::uint64_t>(image_.header.map_offset) + 4U +
                                         static_cast<std::uint64_t>(index) * 12U;
            dex_map_item_t item;
            std::uint16_t unused = 0;
            if (!u16(offset, item.type, "dex.map") || !u16(offset + 2, unused, "dex.map") ||
                !u32(offset + 4, item.size, "dex.map") || !u32(offset + 8, item.offset, "dex.map"))
                return false;
            if (unused != 0)
                return fail(workspace_error_code_t::malformed_image,
                            "DEX map item has a nonzero reserved field", "dex.map", offset + 2, 2);
            if (!seen_types.insert(item.type).second)
                return fail(workspace_error_code_t::malformed_image,
                            "DEX map contains a duplicate item type", "dex.map", offset, 12);
            if (index != 0 && item.offset < previous_offset)
                return fail(workspace_error_code_t::malformed_image,
                            "DEX map item offsets are not ordered", "dex.map", offset + 8, 4);
            previous_offset = item.offset;
            if (item.size != 0 && item.offset >= data_.size())
                return fail(workspace_error_code_t::out_of_range,
                            "DEX map item offset is outside the file", "dex.map", offset + 8, 4);
            if (const auto size = fixed_map_item_size(item.type)) {
                if (item.size != 0 && !require(item.offset,
                                                static_cast<std::uint64_t>(item.size) * *size,
                                                "dex.map"))
                    return false;
            }
            image_.map_items.push_back(item);
            mapped_items.emplace(item.type, item);
        }
        const auto matches_header = [&](std::uint16_t type, std::uint32_t size, std::uint32_t offset) {
            const auto mapped = mapped_items.find(type);
            if (size == 0)
                return mapped == mapped_items.end();
            return mapped != mapped_items.end() && mapped->second.size == size &&
                   mapped->second.offset == offset;
        };
        if (!matches_header(kMapHeaderItem, 1, 0) ||
            !matches_header(kMapMapList, 1, image_.header.map_offset) ||
            !matches_header(kMapStringIdItem, image_.header.string_ids_size, image_.header.string_ids_offset) ||
            !matches_header(kMapTypeIdItem, image_.header.type_ids_size, image_.header.type_ids_offset) ||
            !matches_header(kMapProtoIdItem, image_.header.proto_ids_size, image_.header.proto_ids_offset) ||
            !matches_header(kMapFieldIdItem, image_.header.field_ids_size, image_.header.field_ids_offset) ||
            !matches_header(kMapMethodIdItem, image_.header.method_ids_size, image_.header.method_ids_offset) ||
            !matches_header(kMapClassDefItem, image_.header.class_defs_size, image_.header.class_defs_offset))
            return fail(workspace_error_code_t::malformed_image,
                        "DEX map does not agree with header identifier tables", "dex.map",
                        image_.header.map_offset, 4);
        return true;
    }

    bool append_utf8_codepoint(std::string& output, std::uint32_t codepoint, const char* phase,
                               std::uint32_t offset) {
        if (codepoint <= 0x7fU) {
            output.push_back(static_cast<char>(codepoint));
        } else if (codepoint <= 0x7ffU) {
            output.push_back(static_cast<char>(0xc0U | (codepoint >> 6U)));
            output.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
        } else if (codepoint <= 0xffffU) {
            output.push_back(static_cast<char>(0xe0U | (codepoint >> 12U)));
            output.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3fU)));
            output.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
        } else if (codepoint <= 0x10ffffU) {
            output.push_back(static_cast<char>(0xf0U | (codepoint >> 18U)));
            output.push_back(static_cast<char>(0x80U | ((codepoint >> 12U) & 0x3fU)));
            output.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3fU)));
            output.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
        } else {
            return fail(workspace_error_code_t::malformed_image,
                        "DEX string contains an invalid Unicode codepoint", phase, offset, 1);
        }
        if (output.size() > limits_.max_single_string_bytes)
            return fail(workspace_error_code_t::limit_exceeded,
                        "DEX decoded string exceeds parser limit", phase, offset, output.size());
        return true;
    }

    bool decode_string(std::uint32_t data_offset, dex_string_t& result) {
        std::uint32_t cursor = data_offset;
        if (!uleb(cursor, result.utf16_length, "dex.string"))
            return false;
        if (result.utf16_length > limits_.max_single_string_bytes)
            return fail(workspace_error_code_t::limit_exceeded,
                        "DEX string UTF-16 length exceeds parser limit", "dex.string", data_offset,
                        result.utf16_length);
        result.value.clear();
        result.value.reserve(std::min<std::uint32_t>(result.utf16_length, 4096U));
        std::uint32_t unit_count = 0;
        std::optional<std::uint16_t> high_surrogate;
        while (true) {
            if (!require(cursor, 1, "dex.string"))
                return false;
            const auto first = data_[cursor++];
            if (first == 0)
                break;
            std::uint16_t unit = 0;
            if (first <= 0x7fU) {
                unit = first;
            } else if (first == 0xc0U) {
                if (!require(cursor, 1, "dex.string"))
                    return false;
                const auto second = data_[cursor++];
                if (second != 0x80U)
                    return fail(workspace_error_code_t::malformed_image,
                                "DEX string has an invalid modified UTF-8 NUL", "dex.string", cursor - 2, 2);
                unit = 0;
            } else if (first >= 0xc2U && first <= 0xdfU) {
                if (!require(cursor, 1, "dex.string"))
                    return false;
                const auto second = data_[cursor++];
                if ((second & 0xc0U) != 0x80U)
                    return fail(workspace_error_code_t::malformed_image,
                                "DEX string has an invalid modified UTF-8 continuation", "dex.string", cursor - 2, 2);
                unit = static_cast<std::uint16_t>(((first & 0x1fU) << 6U) | (second & 0x3fU));
            } else if (first >= 0xe0U && first <= 0xefU) {
                if (!require(cursor, 2, "dex.string"))
                    return false;
                const auto second = data_[cursor++];
                const auto third = data_[cursor++];
                if ((second & 0xc0U) != 0x80U || (third & 0xc0U) != 0x80U)
                    return fail(workspace_error_code_t::malformed_image,
                                "DEX string has an invalid modified UTF-8 sequence", "dex.string", cursor - 3, 3);
                unit = static_cast<std::uint16_t>(((first & 0x0fU) << 12U) |
                                                  ((second & 0x3fU) << 6U) | (third & 0x3fU));
            } else {
                return fail(workspace_error_code_t::malformed_image,
                            "DEX string uses an unsupported modified UTF-8 sequence", "dex.string", cursor - 1, 1);
            }
            if (++unit_count > result.utf16_length)
                return fail(workspace_error_code_t::malformed_image,
                            "DEX string exceeds its declared UTF-16 length", "dex.string", data_offset, cursor - data_offset);
            if (unit >= 0xd800U && unit <= 0xdbffU) {
                if (high_surrogate)
                    return fail(workspace_error_code_t::malformed_image,
                                "DEX string has consecutive high surrogates", "dex.string", cursor - 1, 1);
                high_surrogate = unit;
                continue;
            }
            if (unit >= 0xdc00U && unit <= 0xdfffU) {
                if (!high_surrogate)
                    return fail(workspace_error_code_t::malformed_image,
                                "DEX string has an unpaired low surrogate", "dex.string", cursor - 1, 1);
                const auto codepoint = 0x10000U +
                    ((static_cast<std::uint32_t>(*high_surrogate) - 0xd800U) << 10U) +
                    (static_cast<std::uint32_t>(unit) - 0xdc00U);
                high_surrogate.reset();
                if (!append_utf8_codepoint(result.value, codepoint, "dex.string", cursor - 1))
                    return false;
                continue;
            }
            if (high_surrogate)
                return fail(workspace_error_code_t::malformed_image,
                            "DEX string has an unpaired high surrogate", "dex.string", cursor - 1, 1);
            if (!append_utf8_codepoint(result.value, unit, "dex.string", cursor - 1))
                return false;
        }
        if (unit_count != result.utf16_length || high_surrogate)
            return fail(workspace_error_code_t::malformed_image,
                        "DEX string UTF-16 length does not match its encoded data", "dex.string", data_offset,
                        cursor - data_offset);
        if (result.value.size() > limits_.max_string_bytes - total_string_bytes_)
            return fail(workspace_error_code_t::limit_exceeded,
                        "DEX cumulative string bytes exceed parser limit", "dex.string", data_offset,
                        result.value.size());
        total_string_bytes_ += result.value.size();
        return true;
    }

    bool parse_strings() {
        image_.strings.reserve(image_.header.string_ids_size);
        for (std::uint32_t index = 0; index < image_.header.string_ids_size; ++index) {
            if ((index & 255U) == 0 && !poll("dex.strings"))
                return false;
            const auto id_offset = static_cast<std::uint64_t>(image_.header.string_ids_offset) + index * 4ULL;
            dex_string_t string;
            string.index = index;
            if (!u32(id_offset, string.data_offset, "dex.string_ids") ||
                !require(string.data_offset, 1, "dex.string"))
                return false;
            if (!decode_string(string.data_offset, string))
                return false;
            image_.strings.push_back(std::move(string));
        }
        return true;
    }

    bool parse_types() {
        image_.types.reserve(image_.header.type_ids_size);
        for (std::uint32_t index = 0; index < image_.header.type_ids_size; ++index) {
            if ((index & 255U) == 0 && !poll("dex.types"))
                return false;
            dex_type_t type;
            type.index = index;
            const auto offset = static_cast<std::uint64_t>(image_.header.type_ids_offset) + index * 4ULL;
            if (!u32(offset, type.descriptor_string_index, "dex.type_ids"))
                return false;
            if (type.descriptor_string_index >= image_.strings.size())
                return fail(workspace_error_code_t::malformed_image,
                            "DEX type descriptor string index is invalid", "dex.type_ids", offset, 4);
            type.descriptor = image_.strings[type.descriptor_string_index].value;
            image_.types.push_back(std::move(type));
        }
        return true;
    }

    bool parse_type_list(std::uint32_t offset, std::vector<std::uint16_t>& values, const char* phase) {
        if (offset == 0) {
            values.clear();
            return true;
        }
        if ((offset & 3U) != 0)
            return fail(workspace_error_code_t::malformed_image,
                        "DEX type list is not four-byte aligned", phase, offset, 0);
        std::uint32_t size = 0;
        if (!u32(offset, size, phase) || !count_within(size, limits_.max_parameters_per_proto,
                                                       "DEX type list count", offset))
            return false;
        if (!require(static_cast<std::uint64_t>(offset) + 4U, static_cast<std::uint64_t>(size) * 2U, phase))
            return false;
        values.clear();
        values.reserve(size);
        for (std::uint32_t index = 0; index < size; ++index) {
            std::uint16_t type_index = 0;
            if (!u16(static_cast<std::uint64_t>(offset) + 4U + index * 2ULL, type_index, phase))
                return false;
            if (type_index >= image_.types.size())
                return fail(workspace_error_code_t::malformed_image,
                            "DEX type list references an invalid type index", phase,
                            static_cast<std::uint64_t>(offset) + 4U + index * 2ULL, 2);
            values.push_back(type_index);
        }
        return true;
    }

    std::string build_proto_descriptor(const std::vector<std::uint16_t>& parameters,
                                       std::uint32_t return_type_index) {
        std::string descriptor;
        descriptor.push_back('(');
        for (const auto type_index : parameters)
            descriptor.append(image_.types[type_index].descriptor);
        descriptor.push_back(')');
        descriptor.append(image_.types[return_type_index].descriptor);
        return descriptor;
    }

    bool parse_protos() {
        image_.protos.reserve(image_.header.proto_ids_size);
        for (std::uint32_t index = 0; index < image_.header.proto_ids_size; ++index) {
            if ((index & 255U) == 0 && !poll("dex.protos"))
                return false;
            const auto offset = static_cast<std::uint64_t>(image_.header.proto_ids_offset) + index * 12ULL;
            dex_proto_t proto;
            proto.index = index;
            if (!u32(offset, proto.shorty_string_index, "dex.proto_ids") ||
                !u32(offset + 4, proto.return_type_index, "dex.proto_ids") ||
                !u32(offset + 8, proto.parameters_offset, "dex.proto_ids"))
                return false;
            if (proto.shorty_string_index >= image_.strings.size() ||
                proto.return_type_index >= image_.types.size())
                return fail(workspace_error_code_t::malformed_image,
                            "DEX proto references an invalid string or type index", "dex.proto_ids", offset, 12);
            proto.shorty = image_.strings[proto.shorty_string_index].value;
            auto cache = type_list_cache_.find(proto.parameters_offset);
            if (cache == type_list_cache_.end()) {
                std::vector<std::uint16_t> parsed;
                if (!parse_type_list(proto.parameters_offset, parsed, "dex.proto_parameters"))
                    return false;
                cache = type_list_cache_.emplace(proto.parameters_offset, std::move(parsed)).first;
            }
            proto.parameter_type_indices = cache->second;
            proto.descriptor = build_proto_descriptor(proto.parameter_type_indices, proto.return_type_index);
            image_.protos.push_back(std::move(proto));
        }
        return true;
    }

    bool parse_fields() {
        image_.fields.reserve(image_.header.field_ids_size);
        for (std::uint32_t index = 0; index < image_.header.field_ids_size; ++index) {
            if ((index & 255U) == 0 && !poll("dex.fields"))
                return false;
            const auto offset = static_cast<std::uint64_t>(image_.header.field_ids_offset) + index * 8ULL;
            dex_field_t field;
            field.index = index;
            if (!u16(offset, field.class_type_index, "dex.field_ids") ||
                !u16(offset + 2, field.type_index, "dex.field_ids") ||
                !u32(offset + 4, field.name_string_index, "dex.field_ids"))
                return false;
            if (field.class_type_index >= image_.types.size() || field.type_index >= image_.types.size() ||
                field.name_string_index >= image_.strings.size())
                return fail(workspace_error_code_t::malformed_image,
                            "DEX field references an invalid identifier index", "dex.field_ids", offset, 8);
            field.class_descriptor = image_.types[field.class_type_index].descriptor;
            field.type_descriptor = image_.types[field.type_index].descriptor;
            field.name = image_.strings[field.name_string_index].value;
            image_.fields.push_back(std::move(field));
        }
        return true;
    }

    bool parse_methods() {
        image_.methods.reserve(image_.header.method_ids_size);
        for (std::uint32_t index = 0; index < image_.header.method_ids_size; ++index) {
            if ((index & 255U) == 0 && !poll("dex.methods"))
                return false;
            const auto offset = static_cast<std::uint64_t>(image_.header.method_ids_offset) + index * 8ULL;
            dex_method_t method;
            method.index = index;
            if (!u16(offset, method.class_type_index, "dex.method_ids") ||
                !u16(offset + 2, method.proto_index, "dex.method_ids") ||
                !u32(offset + 4, method.name_string_index, "dex.method_ids"))
                return false;
            if (method.class_type_index >= image_.types.size() || method.proto_index >= image_.protos.size() ||
                method.name_string_index >= image_.strings.size())
                return fail(workspace_error_code_t::malformed_image,
                            "DEX method references an invalid identifier index", "dex.method_ids", offset, 8);
            method.class_descriptor = image_.types[method.class_type_index].descriptor;
            method.name = image_.strings[method.name_string_index].value;
            method.descriptor = image_.protos[method.proto_index].descriptor;
            image_.methods.push_back(std::move(method));
        }
        return true;
    }

    bool decode_payload_width(std::uint32_t instruction_offset, std::uint32_t remaining,
                              std::uint16_t opcode_unit, std::uint16_t& width, const char*& mnemonic) {
        const auto subtype = static_cast<std::uint8_t>(opcode_unit >> 8U);
        std::uint16_t count = 0;
        if (subtype == 1U) {
            if (remaining < 4U || !u16(static_cast<std::uint64_t>(instruction_offset) + 2U, count,
                                       "dex.bytecode"))
                return false;
            const auto total = 4ULL + static_cast<std::uint64_t>(count) * 2U;
            if (total > remaining || total > (std::numeric_limits<std::uint16_t>::max)())
                return fail(workspace_error_code_t::malformed_image,
                            "DEX packed-switch payload is truncated", "dex.bytecode", instruction_offset, total);
            width = static_cast<std::uint16_t>(total);
            mnemonic = "packed-switch-payload";
            return true;
        }
        if (subtype == 2U) {
            if (remaining < 2U || !u16(static_cast<std::uint64_t>(instruction_offset) + 2U, count,
                                       "dex.bytecode"))
                return false;
            const auto total = 2ULL + static_cast<std::uint64_t>(count) * 4U;
            if (total > remaining || total > (std::numeric_limits<std::uint16_t>::max)())
                return fail(workspace_error_code_t::malformed_image,
                            "DEX sparse-switch payload is truncated", "dex.bytecode", instruction_offset, total);
            width = static_cast<std::uint16_t>(total);
            mnemonic = "sparse-switch-payload";
            return true;
        }
        if (subtype == 3U) {
            std::uint16_t element_width = 0;
            std::uint32_t element_count = 0;
            if (remaining < 4U || !u16(static_cast<std::uint64_t>(instruction_offset) + 2U, element_width,
                                       "dex.bytecode") ||
                !u32(static_cast<std::uint64_t>(instruction_offset) + 4U, element_count,
                     "dex.bytecode"))
                return false;
            const auto bytes = static_cast<std::uint64_t>(element_width) * element_count;
            const auto total = 4ULL + ((bytes + 1U) / 2U);
            if (total > remaining || total > (std::numeric_limits<std::uint16_t>::max)())
                return fail(workspace_error_code_t::malformed_image,
                            "DEX fill-array-data payload is truncated", "dex.bytecode", instruction_offset, total);
            width = static_cast<std::uint16_t>(total);
            mnemonic = "fill-array-data-payload";
            return true;
        }
        return fail(workspace_error_code_t::malformed_image,
                    "DEX bytecode contains an invalid nop payload discriminator", "dex.bytecode",
                    instruction_offset, 2);
    }

    bool decode_instruction_references(dalvik_instruction_t& instruction, std::uint32_t insns_offset,
                                       std::uint32_t code_unit_offset) {
        const auto opcode = instruction.opcode;
        dalvik_reference_kind_t kind = dalvik_reference_kind_t::none;
        if (is_index_reference_opcode(opcode, kind)) {
            instruction.reference_kind = kind;
            std::uint16_t low = 0;
            if (!u16(static_cast<std::uint64_t>(insns_offset) +
                         static_cast<std::uint64_t>(code_unit_offset + 1U) * 2U,
                     low, "dex.bytecode"))
                return false;
            if (opcode == 0x1bU)
                instruction.reference_index = static_cast<std::uint32_t>(low) |
                    (static_cast<std::uint32_t>(data_[insns_offset + (code_unit_offset + 2U) * 2U]) << 16U) |
                    (static_cast<std::uint32_t>(data_[insns_offset + (code_unit_offset + 2U) * 2U + 1U]) << 24U);
            else
                instruction.reference_index = low;
            const auto reference_valid = [&]() {
                switch (instruction.reference_kind) {
                    case dalvik_reference_kind_t::string:
                        return *instruction.reference_index < image_.strings.size();
                    case dalvik_reference_kind_t::type:
                        return *instruction.reference_index < image_.types.size();
                    case dalvik_reference_kind_t::field:
                        return *instruction.reference_index < image_.fields.size();
                    case dalvik_reference_kind_t::method:
                        return *instruction.reference_index < image_.methods.size();
                    case dalvik_reference_kind_t::proto:
                        return *instruction.reference_index < image_.protos.size();
                    case dalvik_reference_kind_t::call_site:
                    case dalvik_reference_kind_t::method_handle:
                    case dalvik_reference_kind_t::none:
                        return true;
                }
                return false;
            };
            if (!reference_valid())
                return fail(workspace_error_code_t::malformed_image,
                            "DEX instruction references an invalid identifier index", "dex.bytecode",
                            static_cast<std::uint64_t>(insns_offset) +
                                static_cast<std::uint64_t>(code_unit_offset + 1U) * 2U,
                            2);
            if (opcode == 0xfaU || opcode == 0xfbU) {
                std::uint16_t proto = 0;
                if (!u16(static_cast<std::uint64_t>(insns_offset) +
                             static_cast<std::uint64_t>(code_unit_offset + 3U) * 2U,
                         proto, "dex.bytecode"))
                    return false;
                if (proto >= image_.protos.size())
                    return fail(workspace_error_code_t::malformed_image,
                                "DEX invoke-polymorphic instruction references an invalid proto", "dex.bytecode",
                                static_cast<std::uint64_t>(insns_offset) +
                                    static_cast<std::uint64_t>(code_unit_offset + 3U) * 2U,
                                2);
                instruction.secondary_reference_index = proto;
            }
        }
        if (opcode == 0x28U) {
            instruction.branch_target = static_cast<std::int8_t>(instruction.opcode_unit >> 8U) +
                static_cast<std::int32_t>(code_unit_offset);
        } else if (opcode == 0x29U || (opcode >= 0x32U && opcode <= 0x37U)) {
            std::uint16_t target = 0;
            if (!u16(static_cast<std::uint64_t>(insns_offset) +
                         static_cast<std::uint64_t>(code_unit_offset + 1U) * 2U,
                     target, "dex.bytecode"))
                return false;
            instruction.branch_target = sign_extend(target, 16) + static_cast<std::int32_t>(code_unit_offset);
        } else if (opcode == 0x2aU || opcode == 0x2bU || opcode == 0x2cU) {
            std::uint32_t target = 0;
            if (!u32(static_cast<std::uint64_t>(insns_offset) +
                         static_cast<std::uint64_t>(code_unit_offset + 1U) * 2U,
                     target, "dex.bytecode"))
                return false;
            instruction.branch_target = static_cast<std::int32_t>(target) +
                static_cast<std::int32_t>(code_unit_offset);
        }
        return true;
    }

    bool parse_debug_info(std::uint32_t offset, std::uint32_t instruction_count, dex_debug_info_t& info) {
        std::uint32_t cursor = offset;
        info.offset = offset;
        if (!uleb(cursor, info.line_start, "dex.debug") ||
            !poll("dex.debug"))
            return false;
        std::uint32_t parameter_count = 0;
        if (!uleb(cursor, parameter_count, "dex.debug") ||
            !count_within(parameter_count, limits_.max_debug_parameters, "debug parameter count", offset))
            return false;
        info.parameter_name_string_indices.reserve(parameter_count);
        for (std::uint32_t index = 0; index < parameter_count; ++index) {
            std::optional<std::uint32_t> name;
            if (!ulebp1(cursor, name, "dex.debug"))
                return false;
            if (name && *name >= image_.strings.size())
                return fail(workspace_error_code_t::malformed_image,
                            "DEX debug parameter references an invalid string", "dex.debug", cursor, 0);
            info.parameter_name_string_indices.push_back(name);
        }
        std::uint32_t address = 0;
        std::int32_t line = static_cast<std::int32_t>(info.line_start);
        std::optional<std::uint32_t> source_file;
        while (true) {
            if (!require(cursor, 1, "dex.debug"))
                return false;
            const auto opcode = data_[cursor++];
            if (opcode == kDebugEndSequence)
                return true;
            if (opcode == kDebugAdvancePc) {
                std::uint32_t delta = 0;
                if (!uleb(cursor, delta, "dex.debug") || !add_u32(address, delta, address) ||
                    address > instruction_count)
                    return fail(workspace_error_code_t::malformed_image,
                                "DEX debug address advance exceeds method code", "dex.debug", cursor, 0);
                continue;
            }
            if (opcode == kDebugAdvanceLine) {
                std::int32_t delta = 0;
                if (!sleb(cursor, delta, "dex.debug"))
                    return false;
                if ((delta > 0 && line > (std::numeric_limits<std::int32_t>::max)() - delta) ||
                    (delta < 0 && line < (std::numeric_limits<std::int32_t>::min)() - delta))
                    return fail(workspace_error_code_t::malformed_image,
                                "DEX debug line advance overflows", "dex.debug", cursor, 0);
                line += delta;
                continue;
            }
            if (opcode == kDebugStartLocal || opcode == kDebugEndLocal || opcode == kDebugRestartLocal) {
                std::uint32_t register_number = 0;
                if (!uleb(cursor, register_number, "dex.debug"))
                    return false;
                if (opcode == kDebugStartLocal) {
                    std::optional<std::uint32_t> name;
                    std::optional<std::uint32_t> type;
                    if (!ulebp1(cursor, name, "dex.debug") || !ulebp1(cursor, type, "dex.debug"))
                        return false;
                    if ((name && *name >= image_.strings.size()) || (type && *type >= image_.types.size()))
                        return fail(workspace_error_code_t::malformed_image,
                                    "DEX debug local references an invalid identifier", "dex.debug", cursor, 0);
                }
                continue;
            }
            if (opcode == kDebugStartLocalExtended) {
                std::uint32_t register_number = 0;
                std::optional<std::uint32_t> name;
                std::optional<std::uint32_t> type;
                std::optional<std::uint32_t> signature;
                if (!uleb(cursor, register_number, "dex.debug") || !ulebp1(cursor, name, "dex.debug") ||
                    !ulebp1(cursor, type, "dex.debug") || !ulebp1(cursor, signature, "dex.debug"))
                    return false;
                if ((name && *name >= image_.strings.size()) || (type && *type >= image_.types.size()) ||
                    (signature && *signature >= image_.strings.size()))
                    return fail(workspace_error_code_t::malformed_image,
                                "DEX extended debug local references an invalid identifier", "dex.debug", cursor, 0);
                continue;
            }
            if (opcode == kDebugSetPrologueEnd || opcode == kDebugSetEpilogueBegin)
                continue;
            if (opcode == kDebugSetFile) {
                if (!ulebp1(cursor, source_file, "dex.debug"))
                    return false;
                if (source_file && *source_file >= image_.strings.size())
                    return fail(workspace_error_code_t::malformed_image,
                                "DEX debug source file index is invalid", "dex.debug", cursor, 0);
                continue;
            }
            if (opcode < kDebugFirstSpecial)
                return fail(workspace_error_code_t::malformed_image,
                            "DEX debug stream contains an invalid opcode", "dex.debug", cursor - 1, 1);
            const auto adjusted = static_cast<std::uint32_t>(opcode - kDebugFirstSpecial);
            const auto address_delta = adjusted / kDebugLineRange;
            const auto line_delta = static_cast<std::int32_t>(adjusted % kDebugLineRange) + kDebugLineBase;
            if (!add_u32(address, address_delta, address) || address > instruction_count ||
                (line_delta > 0 && line > (std::numeric_limits<std::int32_t>::max)() - line_delta) ||
                (line_delta < 0 && line < (std::numeric_limits<std::int32_t>::min)() - line_delta))
                return fail(workspace_error_code_t::malformed_image,
                            "DEX debug special opcode exceeds method bounds", "dex.debug", cursor - 1, 1);
            line += line_delta;
            if (info.positions.size() >= limits_.max_debug_positions_per_method ||
                total_debug_positions_ >= limits_.max_total_debug_positions)
                return fail(workspace_error_code_t::limit_exceeded,
                            "DEX debug position record limit exceeded", "dex.debug", cursor - 1, 1);
            info.positions.push_back(dex_debug_position_t{address, line, source_file});
            ++total_debug_positions_;
        }
    }

    bool parse_code_item(std::uint32_t offset, std::shared_ptr<const dex_code_item_t>& result) {
        auto cached = code_cache_.find(offset);
        if (cached != code_cache_.end()) {
            result = cached->second;
            return true;
        }
        if ((offset & 3U) != 0 || !require(offset, 16, "dex.code"))
            return fail(workspace_error_code_t::malformed_image,
                        "DEX code item is absent, truncated, or misaligned", "dex.code", offset, 16);
        auto code = std::make_shared<dex_code_item_t>();
        code->offset = offset;
        if (!u16(offset, code->registers_size, "dex.code") ||
            !u16(offset + 2, code->ins_size, "dex.code") ||
            !u16(offset + 4, code->outs_size, "dex.code") ||
            !u16(offset + 6, code->tries_size, "dex.code") ||
            !u32(offset + 8, code->debug_info_offset, "dex.code") ||
            !u32(offset + 12, code->instruction_count, "dex.code"))
            return false;
        if (!count_within(code->instruction_count, limits_.max_code_units_per_method,
                          "code units per method", offset + 12) ||
            !count_within(code->tries_size, limits_.max_try_items_per_method,
                          "try items per method", offset + 6))
            return false;
        if (code->instruction_count > limits_.max_total_code_units - total_code_units_)
            return fail(workspace_error_code_t::limit_exceeded,
                        "DEX cumulative code unit limit exceeded", "dex.code", offset + 12, 4);
        total_code_units_ += code->instruction_count;
        const auto insns_offset = offset + 16U;
        const auto insns_bytes = static_cast<std::uint64_t>(code->instruction_count) * 2U;
        if (!require(insns_offset, insns_bytes, "dex.code"))
            return false;
        code->instructions.reserve(std::min<std::uint32_t>(code->instruction_count, 4096U));
        std::uint32_t cursor = 0;
        while (cursor < code->instruction_count) {
            if ((code->instructions.size() & 1023U) == 0 && !poll("dex.bytecode"))
                return false;
            if (code->instructions.size() >= limits_.max_instruction_records_per_method ||
                total_instruction_records_ >= limits_.max_total_instruction_records)
                return fail(workspace_error_code_t::limit_exceeded,
                            "DEX instruction record limit exceeded", "dex.bytecode",
                            insns_offset + static_cast<std::uint64_t>(cursor) * 2U, 2);
            std::uint16_t opcode_unit = 0;
            if (!u16(static_cast<std::uint64_t>(insns_offset) + static_cast<std::uint64_t>(cursor) * 2U,
                     opcode_unit, "dex.bytecode"))
                return false;
            dalvik_instruction_t instruction;
            instruction.code_unit_offset = cursor;
            instruction.file_offset = provider_offset_ + insns_offset + static_cast<std::uint64_t>(cursor) * 2U;
            instruction.opcode_unit = opcode_unit;
            instruction.opcode = static_cast<std::uint8_t>(opcode_unit & 0xffU);
            instruction.mnemonic = dalvik_opcode_mnemonic(instruction.opcode);
            if (instruction.opcode == 0 && opcode_unit != 0) {
                instruction.payload = true;
                if (!decode_payload_width(insns_offset + cursor * 2U, code->instruction_count - cursor,
                                          opcode_unit, instruction.width_code_units, instruction.mnemonic))
                    return false;
            } else {
                instruction.width_code_units = dalvik_opcode_width(instruction.opcode);
                if (instruction.width_code_units == 0)
                    return fail(workspace_error_code_t::decode_failure,
                                "DEX bytecode contains an unsupported or reserved opcode", "dex.bytecode",
                                insns_offset + static_cast<std::uint64_t>(cursor) * 2U, 2);
                if (instruction.width_code_units > code->instruction_count - cursor)
                    return fail(workspace_error_code_t::malformed_image,
                                "DEX bytecode instruction is truncated", "dex.bytecode",
                                insns_offset + static_cast<std::uint64_t>(cursor) * 2U,
                                static_cast<std::uint64_t>(instruction.width_code_units) * 2U);
                if (!decode_instruction_references(instruction, insns_offset, cursor))
                    return false;
            }
            code->instructions.push_back(std::move(instruction));
            ++total_instruction_records_;
            cursor += code->instructions.back().width_code_units;
        }
        for (const auto& instruction : code->instructions) {
            if (!instruction.branch_target)
                continue;
            if (*instruction.branch_target < 0 ||
                static_cast<std::uint32_t>(*instruction.branch_target) >= code->instruction_count)
                return fail(workspace_error_code_t::malformed_image,
                            "DEX bytecode branch target is outside method code", "dex.bytecode",
                            insns_offset + static_cast<std::uint64_t>(instruction.code_unit_offset) * 2U, 2);
        }
        std::uint64_t tail = static_cast<std::uint64_t>(insns_offset) + insns_bytes;
        if (code->tries_size != 0 && (code->instruction_count & 1U) != 0) {
            if (!require(tail, 2, "dex.code"))
                return false;
            tail += 2;
        }
        const auto tries_bytes = static_cast<std::uint64_t>(code->tries_size) * 8U;
        if (!require(tail, tries_bytes, "dex.code"))
            return false;
        code->tries.reserve(code->tries_size);
        for (std::uint32_t index = 0; index < code->tries_size; ++index) {
            dex_try_item_t item;
            const auto try_offset = tail + index * 8ULL;
            if (!u32(try_offset, item.start_address, "dex.try") ||
                !u16(try_offset + 4, item.instruction_count, "dex.try") ||
                !u16(try_offset + 6, item.handler_offset, "dex.try"))
                return false;
            if (item.start_address > code->instruction_count ||
                item.instruction_count > code->instruction_count - item.start_address)
                return fail(workspace_error_code_t::malformed_image,
                            "DEX try range exceeds method code", "dex.try", try_offset, 8);
            code->tries.push_back(item);
        }
        tail += tries_bytes;
        if (code->tries_size != 0) {
            const auto handlers_base = static_cast<std::uint32_t>(tail);
            std::uint32_t handlers_cursor = handlers_base;
            std::uint32_t handler_count = 0;
            if (!uleb(handlers_cursor, handler_count, "dex.handlers") ||
                !count_within(handler_count, limits_.max_catch_handlers_per_method,
                              "catch handler count", handlers_base))
                return false;
            std::unordered_set<std::uint32_t> handler_offsets;
            for (std::uint32_t index = 0; index < handler_count; ++index) {
                if ((index & 255U) == 0 && !poll("dex.handlers"))
                    return false;
                dex_catch_handler_t handler;
                handler.relative_offset = handlers_cursor - handlers_base;
                handler_offsets.insert(handler.relative_offset);
                std::int32_t signed_size = 0;
                if (!sleb(handlers_cursor, signed_size, "dex.handlers"))
                    return false;
                const auto pair_count = signed_size < 0
                    ? static_cast<std::uint64_t>(-static_cast<std::int64_t>(signed_size))
                    : static_cast<std::uint64_t>(signed_size);
                if (pair_count > limits_.max_catch_pairs_per_handler)
                    return fail(workspace_error_code_t::limit_exceeded,
                                "DEX catch handler pair count exceeds parser limit", "dex.handlers",
                                handlers_cursor, pair_count);
                handler.typed_handlers.reserve(static_cast<std::size_t>(pair_count));
                for (std::uint64_t pair = 0; pair < pair_count; ++pair) {
                    std::uint32_t type_index = 0;
                    std::uint32_t address = 0;
                    if (!uleb(handlers_cursor, type_index, "dex.handlers") ||
                        !uleb(handlers_cursor, address, "dex.handlers"))
                        return false;
                    if (type_index >= image_.types.size() || address >= code->instruction_count)
                        return fail(workspace_error_code_t::malformed_image,
                                    "DEX catch handler references an invalid type or address", "dex.handlers",
                                    handlers_cursor, 0);
                    handler.typed_handlers.emplace_back(type_index, address);
                }
                if (signed_size <= 0) {
                    std::uint32_t address = 0;
                    if (!uleb(handlers_cursor, address, "dex.handlers"))
                        return false;
                    if (address >= code->instruction_count)
                        return fail(workspace_error_code_t::malformed_image,
                                    "DEX catch-all handler address exceeds method code", "dex.handlers",
                                    handlers_cursor, 0);
                    handler.catch_all_address = address;
                }
                code->catch_handlers.push_back(std::move(handler));
            }
            for (const auto& item : code->tries) {
                if (handler_offsets.find(item.handler_offset) == handler_offsets.end())
                    return fail(workspace_error_code_t::malformed_image,
                                "DEX try item references an unknown catch handler", "dex.try",
                                tail, item.handler_offset);
            }
        }
        if (code->debug_info_offset != 0) {
            if (!require(code->debug_info_offset, 1, "dex.debug"))
                return false;
            dex_debug_info_t info;
            if (!parse_debug_info(code->debug_info_offset, code->instruction_count, info))
                return false;
            code->debug_info = std::move(info);
        }
        result = code;
        code_cache_.emplace(offset, std::move(code));
        return true;
    }

    bool parse_encoded_fields(std::uint32_t& cursor, std::uint32_t count, bool is_static,
                              std::uint32_t class_type_index,
                              std::vector<dex_encoded_field_t>& destination) {
        if (!count_within(count, limits_.max_class_data_items, "encoded field count", cursor))
            return false;
        destination.reserve(count);
        std::uint32_t current_index = 0;
        for (std::uint32_t index = 0; index < count; ++index) {
            std::uint32_t diff = 0;
            dex_encoded_field_t field;
            if (!uleb(cursor, diff, "dex.class_data") || !uleb(cursor, field.access_flags, "dex.class_data"))
                return false;
            if (index == 0) {
                current_index = diff;
            } else if (diff == 0 || !add_u32(current_index, diff, current_index)) {
                return fail(workspace_error_code_t::malformed_image,
                            "DEX encoded field indices are not strictly increasing", "dex.class_data", cursor, 0);
            }
            if (current_index >= image_.fields.size() ||
                image_.fields[current_index].class_type_index != class_type_index)
                return fail(workspace_error_code_t::malformed_image,
                            "DEX encoded field does not belong to its class", "dex.class_data", cursor, 0);
            field.field_index = current_index;
            field.is_static = is_static;
            destination.push_back(field);
        }
        return true;
    }

    bool parse_encoded_methods(std::uint32_t& cursor, std::uint32_t count, bool is_direct,
                               std::uint32_t class_type_index,
                               std::vector<dex_encoded_method_t>& destination) {
        if (!count_within(count, limits_.max_class_data_items, "encoded method count", cursor))
            return false;
        destination.reserve(count);
        std::uint32_t current_index = 0;
        for (std::uint32_t index = 0; index < count; ++index) {
            std::uint32_t diff = 0;
            dex_encoded_method_t method;
            if (!uleb(cursor, diff, "dex.class_data") || !uleb(cursor, method.access_flags, "dex.class_data") ||
                !uleb(cursor, method.code_offset, "dex.class_data"))
                return false;
            if (index == 0) {
                current_index = diff;
            } else if (diff == 0 || !add_u32(current_index, diff, current_index)) {
                return fail(workspace_error_code_t::malformed_image,
                            "DEX encoded method indices are not strictly increasing", "dex.class_data", cursor, 0);
            }
            if (current_index >= image_.methods.size() ||
                image_.methods[current_index].class_type_index != class_type_index)
                return fail(workspace_error_code_t::malformed_image,
                            "DEX encoded method does not belong to its class", "dex.class_data", cursor, 0);
            method.method_index = current_index;
            method.is_direct = is_direct;
            if (method.code_offset != 0 && !parse_code_item(method.code_offset, method.code))
                return false;
            destination.push_back(std::move(method));
        }
        return true;
    }

    bool parse_class_data(dex_class_def_t& definition) {
        if (definition.class_data_offset == 0)
            return true;
        if (!require(definition.class_data_offset, 1, "dex.class_data"))
            return false;
        std::uint32_t cursor = definition.class_data_offset;
        std::uint32_t static_field_count = 0;
        std::uint32_t instance_field_count = 0;
        std::uint32_t direct_method_count = 0;
        std::uint32_t virtual_method_count = 0;
        if (!uleb(cursor, static_field_count, "dex.class_data") ||
            !uleb(cursor, instance_field_count, "dex.class_data") ||
            !uleb(cursor, direct_method_count, "dex.class_data") ||
            !uleb(cursor, virtual_method_count, "dex.class_data"))
            return false;
        return parse_encoded_fields(cursor, static_field_count, true, definition.class_type_index,
                                    definition.static_fields) &&
               parse_encoded_fields(cursor, instance_field_count, false, definition.class_type_index,
                                    definition.instance_fields) &&
               parse_encoded_methods(cursor, direct_method_count, true, definition.class_type_index,
                                     definition.direct_methods) &&
               parse_encoded_methods(cursor, virtual_method_count, false, definition.class_type_index,
                                     definition.virtual_methods);
    }

    bool parse_classes() {
        image_.classes.reserve(image_.header.class_defs_size);
        std::uint32_t previous_type_index = 0;
        for (std::uint32_t index = 0; index < image_.header.class_defs_size; ++index) {
            if ((index & 63U) == 0 && !poll("dex.classes"))
                return false;
            const auto offset = static_cast<std::uint64_t>(image_.header.class_defs_offset) + index * 32ULL;
            dex_class_def_t definition;
            definition.index = index;
            if (!u32(offset, definition.class_type_index, "dex.class_defs") ||
                !u32(offset + 4, definition.access_flags, "dex.class_defs") ||
                !u32(offset + 8, definition.superclass_type_index, "dex.class_defs") ||
                !u32(offset + 12, definition.interfaces_offset, "dex.class_defs") ||
                !u32(offset + 16, definition.source_file_string_index, "dex.class_defs") ||
                !u32(offset + 20, definition.annotations_offset, "dex.class_defs") ||
                !u32(offset + 24, definition.class_data_offset, "dex.class_defs") ||
                !u32(offset + 28, definition.static_values_offset, "dex.class_defs"))
                return false;
            if (definition.class_type_index >= image_.types.size() ||
                (index != 0 && definition.class_type_index <= previous_type_index))
                return fail(workspace_error_code_t::malformed_image,
                            "DEX class definitions have invalid or unordered type indices", "dex.class_defs", offset, 4);
            previous_type_index = definition.class_type_index;
            if (definition.superclass_type_index != kNoIndex &&
                definition.superclass_type_index >= image_.types.size())
                return fail(workspace_error_code_t::malformed_image,
                            "DEX class has an invalid superclass type index", "dex.class_defs", offset + 8, 4);
            if (definition.source_file_string_index != kNoIndex &&
                definition.source_file_string_index >= image_.strings.size())
                return fail(workspace_error_code_t::malformed_image,
                            "DEX class has an invalid source file string index", "dex.class_defs", offset + 16, 4);
            if (!parse_type_list(definition.interfaces_offset, definition.interface_type_indices,
                                 "dex.class_interfaces"))
                return false;
            definition.class_descriptor = image_.types[definition.class_type_index].descriptor;
            if (definition.superclass_type_index != kNoIndex)
                definition.superclass_descriptor = image_.types[definition.superclass_type_index].descriptor;
            if (definition.source_file_string_index != kNoIndex)
                definition.source_file = image_.strings[definition.source_file_string_index].value;
            if (definition.annotations_offset != 0 && !require(definition.annotations_offset, 1, "dex.annotations"))
                return false;
            if (definition.static_values_offset != 0 && !require(definition.static_values_offset, 1, "dex.static_values"))
                return false;
            if (!parse_class_data(definition))
                return false;
            image_.managed_identity.class_descriptors.push_back(definition.class_descriptor);
            if (definition.source_file)
                image_.managed_identity.source_files.push_back(*definition.source_file);
            image_.classes.push_back(std::move(definition));
        }
        std::sort(image_.managed_identity.source_files.begin(), image_.managed_identity.source_files.end());
        image_.managed_identity.source_files.erase(
            std::unique(image_.managed_identity.source_files.begin(), image_.managed_identity.source_files.end()),
            image_.managed_identity.source_files.end());
        return true;
    }

    bool add_section(std::uint32_t index, std::string name, std::uint64_t address,
                     std::uint64_t size, std::uint32_t permissions) {
        if (size == 0)
            return true;
        image_section_t section;
        section.index = index;
        section.name = std::move(name);
        section.virtual_address = address;
        section.virtual_size = size;
        section.file_offset = provider_offset_ + address;
        section.file_size = size;
        section.permissions = permissions;
        image_.normalized.sections.push_back(std::move(section));
        return true;
    }

    bool add_table_section(std::uint32_t index, const char* name, std::uint32_t offset,
                           std::uint32_t count, std::uint32_t element_size) {
        if (count == 0)
            return true;
        return add_section(index, name, offset, static_cast<std::uint64_t>(count) * element_size,
                           image_permission_read);
    }

    bool append_method_symbols(const std::vector<dex_encoded_method_t>& methods) {
        for (const auto& encoded : methods) {
            if (!encoded.code)
                continue;
            if (!poll("dex.normalize"))
                return false;
            const auto& method = image_.methods[encoded.method_index];
            image_symbol_t symbol;
            symbol.ordinal = encoded.method_index;
            symbol.name = method.class_descriptor;
            symbol.name.append("->");
            symbol.name.append(method.name);
            symbol.name.append(method.descriptor);
            symbol.address = address_t{address_space_id_t::relative_virtual, encoded.code_offset,
                                       architecture_id_t::dalvik_bytecode, architecture_mode_t::dalvik};
            symbol.size = static_cast<std::uint64_t>(encoded.code->instruction_count) * 2U;
            symbol.kind = image_symbol_kind_t::function;
            symbol.binding = image_symbol_binding_t::global;
            symbol.defined = true;
            image_.normalized.symbols.push_back(std::move(symbol));
        }
        return true;
    }

    bool build_normalized() {
        auto& normalized = image_.normalized;
        normalized.format = container_.kind == dex_container_kind_t::dex ? format_id_t::dex :
                            container_.kind == dex_container_kind_t::oat ? format_id_t::oat :
                            container_.kind == dex_container_kind_t::vdex ? format_id_t::vdex :
                            format_id_t::dex;
        normalized.architecture = architecture_id_t::dalvik_bytecode;
        normalized.architecture_mode = architecture_mode_t::dalvik;
        normalized.abi = abi_id_t::dalvik;
        normalized.endian = endian_t::little;
        normalized.address_width_bits = 32;
        normalized.image_base = 0;
        normalized.image_size = image_.header.file_size;
        normalized.header_size = image_.header.header_size;
        normalized.format_name = std::string(dex_container_kind_name(container_.kind));
        normalized.format_name.push_back(':');
        normalized.format_name.append(image_.managed_identity.version);
        normalized.provider_source = identity_.normalized_source;
        normalized.provider_size = provider_size_;
        normalized.member = identity_.member;
        image_segment_t segment;
        segment.index = 0;
        segment.name = "dex";
        segment.virtual_address = 0;
        segment.virtual_size = image_.header.file_size;
        segment.file_offset = provider_offset_;
        segment.file_size = image_.header.file_size;
        segment.permissions = image_permission_read | image_permission_execute;
        normalized.segments.push_back(std::move(segment));
        image_address_mapping_t mapping;
        mapping.source_start = provider_offset_;
        mapping.target_start = 0;
        mapping.size = image_.header.file_size;
        mapping.permissions = image_permission_read | image_permission_execute;
        normalized.address_mappings.push_back(mapping);
        if (!add_section(0, "header", 0, image_.header.header_size, image_permission_read) ||
            !add_table_section(1, "string_ids", image_.header.string_ids_offset,
                               image_.header.string_ids_size, 4) ||
            !add_table_section(2, "type_ids", image_.header.type_ids_offset,
                               image_.header.type_ids_size, 4) ||
            !add_table_section(3, "proto_ids", image_.header.proto_ids_offset,
                               image_.header.proto_ids_size, 12) ||
            !add_table_section(4, "field_ids", image_.header.field_ids_offset,
                               image_.header.field_ids_size, 8) ||
            !add_table_section(5, "method_ids", image_.header.method_ids_offset,
                               image_.header.method_ids_size, 8) ||
            !add_table_section(6, "class_defs", image_.header.class_defs_offset,
                               image_.header.class_defs_size, 32) ||
            !add_section(7, "data", image_.header.data_offset, image_.header.data_size,
                         image_permission_read | image_permission_execute))
            return false;
        for (const auto& definition : image_.classes) {
            if (!poll("dex.normalize"))
                return false;
            image_symbol_t class_symbol;
            class_symbol.ordinal = definition.index;
            class_symbol.name = definition.class_descriptor;
            class_symbol.address = address_t{address_space_id_t::relative_virtual,
                                             image_.header.class_defs_offset + definition.index * 32ULL,
                                             architecture_id_t::dalvik_bytecode,
                                             architecture_mode_t::dalvik};
            class_symbol.size = 32;
            class_symbol.kind = image_symbol_kind_t::type_symbol;
            class_symbol.binding = image_symbol_binding_t::global;
            class_symbol.defined = true;
            normalized.symbols.push_back(std::move(class_symbol));
            if (!append_method_symbols(definition.direct_methods) ||
                !append_method_symbols(definition.virtual_methods))
                return false;
        }
        auto validation = validate_workspace_image(normalized, {}, false, cancel_);
        if (!validation) {
            error_ = validation.error();
            failed_ = true;
            return false;
        }
        return true;
    }

    const std::vector<std::uint8_t>& data_;
    std::uint64_t provider_offset_ = 0;
    std::uint64_t provider_size_ = 0;
    const byte_provider_identity_t& identity_;
    dex_container_info_t container_;
    const dex_parse_limits_t& limits_;
    const cancellation_token_t& cancel_;
    dex_image_t image_;
    workspace_error_t error_;
    bool failed_ = false;
    std::uint64_t total_string_bytes_ = 0;
    std::uint64_t total_code_units_ = 0;
    std::uint64_t total_instruction_records_ = 0;
    std::uint64_t total_debug_positions_ = 0;
    std::unordered_map<std::uint32_t, std::vector<std::uint16_t>> type_list_cache_;
    std::unordered_map<std::uint32_t, std::shared_ptr<const dex_code_item_t>> code_cache_;
};

workspace_result_t<std::vector<std::uint8_t>> read_prefix(const byte_provider_t& provider,
                                                          std::uint64_t max_size,
                                                          const cancellation_token_t& cancel) {
    const auto size = std::min(provider.size(), max_size);
    if (size == 0)
        return workspace_result_t<std::vector<std::uint8_t>>::success({});
    return provider.read_vector(0, size, max_size, cancel);
}

workspace_result_t<dex_container_info_t> detect_from_prefix(const std::vector<std::uint8_t>& data) {
    dex_container_info_t info;
    if (is_dex_magic(data.data(), data.size())) {
        info.kind = dex_container_kind_t::dex;
        info.version = make_version(data.data() + 4, 3);
        info.header_size = kDexHeaderSize;
    } else if (is_compact_dex_magic(data.data(), data.size())) {
        info.kind = dex_container_kind_t::compact_dex;
        info.version = make_version(data.data() + 4, 3);
        info.header_size = 8;
    } else if (data.size() >= 8 && std::memcmp(data.data(), "oat\n", 4) == 0 &&
               is_decimal_version(data.data() + 4)) {
        info.kind = dex_container_kind_t::oat;
        info.version = make_version(data.data() + 4, 3);
        info.header_size = 8;
    } else if (data.size() >= 8 && std::memcmp(data.data(), "vdex", 4) == 0 &&
               is_decimal_version(data.data() + 4)) {
        info.kind = dex_container_kind_t::vdex;
        info.version = make_version(data.data() + 4, 3);
        info.header_size = 8;
    }
    return workspace_result_t<dex_container_info_t>::success(std::move(info));
}

workspace_result_t<dex_image_t> parse_dex_at(const byte_provider_t& provider, std::uint64_t offset,
                                              dex_container_info_t container,
                                              const dex_parse_limits_t& limits,
                                              const cancellation_token_t& cancel) {
    if (cancel.stop_requested())
        return workspace_result_t<dex_image_t>::failure(dex_stop_error(cancel, "dex.read"));
    if (!span_within(offset, kDexHeaderSize, provider.size()))
        return workspace_result_t<dex_image_t>::failure(dex_error(
            workspace_error_code_t::out_of_range, "DEX header is truncated", "dex.read", offset, kDexHeaderSize));
    auto header_result = provider.read_vector(offset, kDexHeaderSize, kDexHeaderSize, cancel);
    if (!header_result)
        return workspace_result_t<dex_image_t>::failure(header_result.error());
    const auto& header = header_result.value();
    if (!is_dex_magic(header.data(), header.size()))
        return workspace_result_t<dex_image_t>::failure(dex_error(
            workspace_error_code_t::unsupported_format, "DEX payload magic is invalid", "dex.read", offset, 8));
    const auto file_size = read_u32_le(header.data() + 32);
    if (file_size < kDexHeaderSize || file_size > limits.max_file_size ||
        !span_within(offset, file_size, provider.size()))
        return workspace_result_t<dex_image_t>::failure(dex_error(
            file_size > limits.max_file_size ? workspace_error_code_t::limit_exceeded
                                              : workspace_error_code_t::out_of_range,
            "DEX payload size is invalid or exceeds the parser limit", "dex.read", offset + 32, 4));
    auto data_result = provider.read_vector(offset, file_size, limits.max_file_size, cancel);
    if (!data_result)
        return workspace_result_t<dex_image_t>::failure(data_result.error());
    dex_parser_t parser(data_result.value(), offset, provider.size(), provider.identity(),
                        std::move(container), limits, cancel);
    return parser.parse();
}

workspace_image_t make_container_workspace_image(const byte_provider_t& provider,
                                                  const dex_container_info_t& container) {
    workspace_image_t image;
    image.format = container.kind == dex_container_kind_t::oat ? format_id_t::oat : format_id_t::vdex;
    image.architecture = architecture_id_t::dalvik_bytecode;
    image.architecture_mode = architecture_mode_t::dalvik;
    image.abi = abi_id_t::dalvik;
    image.endian = endian_t::little;
    image.address_width_bits = 32;
    image.image_size = provider.size();
    image.header_size = container.header_size;
    image.format_name = std::string(dex_container_kind_name(container.kind)) + ":" + container.version;
    image.provider_source = provider.identity().normalized_source;
    image.provider_size = provider.size();
    image.member = provider.member_metadata();
    image_segment_t segment;
    segment.name = dex_container_kind_name(container.kind);
    segment.virtual_size = provider.size();
    segment.file_size = provider.size();
    segment.permissions = image_permission_read;
    image.segments.push_back(std::move(segment));
    image_address_mapping_t mapping;
    mapping.size = provider.size();
    mapping.permissions = image_permission_read;
    image.address_mappings.push_back(mapping);
    image_section_t header;
    header.name = "header";
    header.virtual_size = container.header_size;
    header.file_size = container.header_size;
    header.permissions = image_permission_read;
    image.sections.push_back(std::move(header));
    return image;
}

workspace_result_t<dex_image_t> parse_container(const byte_provider_t& provider,
                                                 dex_container_info_t container,
                                                 const dex_parse_limits_t& limits,
                                                 const cancellation_token_t& cancel) {
    if (provider.size() > limits.max_container_scan_bytes) {
        auto scan_result = provider.read_vector(0, limits.max_container_scan_bytes,
                                                limits.max_container_scan_bytes, cancel);
        if (!scan_result)
            return workspace_result_t<dex_image_t>::failure(scan_result.error());
        auto scan = scan_result.take_value();
        for (std::uint64_t offset = 0; offset + 8 <= scan.size(); ++offset) {
            if (!is_dex_magic(scan.data() + offset, scan.size() - static_cast<std::size_t>(offset)))
                continue;
            if (container.embedded_dex_offsets.size() >= limits.max_embedded_dex_files)
                return workspace_result_t<dex_image_t>::failure(dex_error(
                    workspace_error_code_t::limit_exceeded, "embedded DEX candidate limit exceeded",
                    "dex.container", offset, 8));
            container.embedded_dex_offsets.push_back(offset);
        }
    } else {
        auto scan_result = provider.read_vector(0, provider.size(), limits.max_container_scan_bytes, cancel);
        if (!scan_result)
            return workspace_result_t<dex_image_t>::failure(scan_result.error());
        auto scan = scan_result.take_value();
        for (std::uint64_t offset = 0; offset + 8 <= scan.size(); ++offset) {
            if (!is_dex_magic(scan.data() + offset, scan.size() - static_cast<std::size_t>(offset)))
                continue;
            if (container.embedded_dex_offsets.size() >= limits.max_embedded_dex_files)
                return workspace_result_t<dex_image_t>::failure(dex_error(
                    workspace_error_code_t::limit_exceeded, "embedded DEX candidate limit exceeded",
                    "dex.container", offset, 8));
            container.embedded_dex_offsets.push_back(offset);
        }
    }
    for (const auto offset : container.embedded_dex_offsets) {
        auto parsed = parse_dex_at(provider, offset, container, limits, cancel);
        if (!parsed)
            continue;
        auto image = parsed.take_value();
        image.container = container;
        image.managed_identity.container_kind = container.kind;
        image.normalized.format = container.kind == dex_container_kind_t::oat ? format_id_t::oat : format_id_t::vdex;
        image.normalized.format_name = std::string(dex_container_kind_name(container.kind)) + ":" +
                                     container.version + "/dex:" + image.managed_identity.version;
        return workspace_result_t<dex_image_t>::success(std::move(image));
    }
    dex_image_t image;
    image.container = container;
    image.managed_identity.container_kind = container.kind;
    image.managed_identity.version = container.version;
    image.normalized = make_container_workspace_image(provider, container);
    auto validation = validate_workspace_image(image.normalized, {}, false, cancel);
    if (!validation)
        return workspace_result_t<dex_image_t>::failure(validation.error());
    return workspace_result_t<dex_image_t>::success(std::move(image));
}

}

const char* dex_container_kind_name(dex_container_kind_t kind) noexcept {
    switch (kind) {
        case dex_container_kind_t::dex: return "dex";
        case dex_container_kind_t::compact_dex: return "compact-dex";
        case dex_container_kind_t::oat: return "oat";
        case dex_container_kind_t::vdex: return "vdex";
        case dex_container_kind_t::unknown: return "unknown";
    }
    return "unknown";
}

const char* dalvik_opcode_mnemonic(std::uint8_t opcode) noexcept {
    switch (opcode) {
        case 0x00: return "nop"; case 0x01: return "move"; case 0x02: return "move/from16";
        case 0x03: return "move/16"; case 0x04: return "move-wide"; case 0x05: return "move-wide/from16";
        case 0x06: return "move-wide/16"; case 0x07: return "move-object"; case 0x08: return "move-object/from16";
        case 0x09: return "move-object/16"; case 0x0a: return "move-result"; case 0x0b: return "move-result-wide";
        case 0x0c: return "move-result-object"; case 0x0d: return "move-exception"; case 0x0e: return "return-void";
        case 0x0f: return "return"; case 0x10: return "return-wide"; case 0x11: return "return-object";
        case 0x12: return "const/4"; case 0x13: return "const/16"; case 0x14: return "const";
        case 0x15: return "const/high16"; case 0x16: return "const-wide/16"; case 0x17: return "const-wide/32";
        case 0x18: return "const-wide"; case 0x19: return "const-wide/high16"; case 0x1a: return "const-string";
        case 0x1b: return "const-string/jumbo"; case 0x1c: return "const-class"; case 0x1d: return "monitor-enter";
        case 0x1e: return "monitor-exit"; case 0x1f: return "check-cast"; case 0x20: return "instance-of";
        case 0x21: return "array-length"; case 0x22: return "new-instance"; case 0x23: return "new-array";
        case 0x24: return "filled-new-array"; case 0x25: return "filled-new-array/range"; case 0x26: return "fill-array-data";
        case 0x27: return "throw"; case 0x28: return "goto"; case 0x29: return "goto/16";
        case 0x2a: return "goto/32"; case 0x2b: return "packed-switch"; case 0x2c: return "sparse-switch";
        case 0x2d: return "cmpl-float"; case 0x2e: return "cmpg-float"; case 0x2f: return "cmpl-double";
        case 0x30: return "cmpg-double"; case 0x31: return "cmp-long"; case 0x32: return "if-eq";
        case 0x33: return "if-ne"; case 0x34: return "if-lt"; case 0x35: return "if-ge";
        case 0x36: return "if-gt"; case 0x37: return "if-le"; case 0x38: return "if-eqz";
        case 0x39: return "if-nez"; case 0x3a: return "if-ltz"; case 0x3b: return "if-gez";
        case 0x3c: return "if-gtz"; case 0x3d: return "if-lez";
        case 0x44: return "aget"; case 0x45: return "aget-wide"; case 0x46: return "aget-object";
        case 0x47: return "aget-boolean"; case 0x48: return "aget-byte"; case 0x49: return "aget-char";
        case 0x4a: return "aget-short"; case 0x4b: return "aput"; case 0x4c: return "aput-wide";
        case 0x4d: return "aput-object"; case 0x4e: return "aput-boolean"; case 0x4f: return "aput-byte";
        case 0x50: return "aput-char"; case 0x51: return "aput-short";
        case 0x52: return "iget"; case 0x53: return "iget-wide"; case 0x54: return "iget-object";
        case 0x55: return "iget-boolean"; case 0x56: return "iget-byte"; case 0x57: return "iget-char";
        case 0x58: return "iget-short"; case 0x59: return "iput"; case 0x5a: return "iput-wide";
        case 0x5b: return "iput-object"; case 0x5c: return "iput-boolean"; case 0x5d: return "iput-byte";
        case 0x5e: return "iput-char"; case 0x5f: return "iput-short";
        case 0x60: return "sget"; case 0x61: return "sget-wide"; case 0x62: return "sget-object";
        case 0x63: return "sget-boolean"; case 0x64: return "sget-byte"; case 0x65: return "sget-char";
        case 0x66: return "sget-short"; case 0x67: return "sput"; case 0x68: return "sput-wide";
        case 0x69: return "sput-object"; case 0x6a: return "sput-boolean"; case 0x6b: return "sput-byte";
        case 0x6c: return "sput-char"; case 0x6d: return "sput-short";
        case 0x6e: return "invoke-virtual"; case 0x6f: return "invoke-super"; case 0x70: return "invoke-direct";
        case 0x71: return "invoke-static"; case 0x72: return "invoke-interface";
        case 0x74: return "invoke-virtual/range"; case 0x75: return "invoke-super/range";
        case 0x76: return "invoke-direct/range"; case 0x77: return "invoke-static/range";
        case 0x78: return "invoke-interface/range";
        case 0x7b: return "neg-int"; case 0x7c: return "not-int"; case 0x7d: return "neg-long";
        case 0x7e: return "not-long"; case 0x7f: return "neg-float"; case 0x80: return "neg-double";
        case 0x81: return "int-to-long"; case 0x82: return "int-to-float"; case 0x83: return "int-to-double";
        case 0x84: return "long-to-int"; case 0x85: return "long-to-float"; case 0x86: return "long-to-double";
        case 0x87: return "float-to-int"; case 0x88: return "float-to-long"; case 0x89: return "float-to-double";
        case 0x8a: return "double-to-int"; case 0x8b: return "double-to-long"; case 0x8c: return "double-to-float";
        case 0x8d: return "int-to-byte"; case 0x8e: return "int-to-char"; case 0x8f: return "int-to-short";
        case 0x90: return "add-int"; case 0x91: return "sub-int"; case 0x92: return "mul-int";
        case 0x93: return "div-int"; case 0x94: return "rem-int"; case 0x95: return "and-int";
        case 0x96: return "or-int"; case 0x97: return "xor-int"; case 0x98: return "shl-int";
        case 0x99: return "shr-int"; case 0x9a: return "ushr-int"; case 0x9b: return "add-long";
        case 0x9c: return "sub-long"; case 0x9d: return "mul-long"; case 0x9e: return "div-long";
        case 0x9f: return "rem-long"; case 0xa0: return "and-long"; case 0xa1: return "or-long";
        case 0xa2: return "xor-long"; case 0xa3: return "shl-long"; case 0xa4: return "shr-long";
        case 0xa5: return "ushr-long"; case 0xa6: return "add-float"; case 0xa7: return "sub-float";
        case 0xa8: return "mul-float"; case 0xa9: return "div-float"; case 0xaa: return "rem-float";
        case 0xab: return "add-double"; case 0xac: return "sub-double"; case 0xad: return "mul-double";
        case 0xae: return "div-double"; case 0xaf: return "rem-double";
        case 0xb0: return "add-int/2addr"; case 0xb1: return "sub-int/2addr"; case 0xb2: return "mul-int/2addr";
        case 0xb3: return "div-int/2addr"; case 0xb4: return "rem-int/2addr"; case 0xb5: return "and-int/2addr";
        case 0xb6: return "or-int/2addr"; case 0xb7: return "xor-int/2addr"; case 0xb8: return "shl-int/2addr";
        case 0xb9: return "shr-int/2addr"; case 0xba: return "ushr-int/2addr"; case 0xbb: return "add-long/2addr";
        case 0xbc: return "sub-long/2addr"; case 0xbd: return "mul-long/2addr"; case 0xbe: return "div-long/2addr";
        case 0xbf: return "rem-long/2addr"; case 0xc0: return "and-long/2addr"; case 0xc1: return "or-long/2addr";
        case 0xc2: return "xor-long/2addr"; case 0xc3: return "shl-long/2addr"; case 0xc4: return "shr-long/2addr";
        case 0xc5: return "ushr-long/2addr"; case 0xc6: return "add-float/2addr"; case 0xc7: return "sub-float/2addr";
        case 0xc8: return "mul-float/2addr"; case 0xc9: return "div-float/2addr"; case 0xca: return "rem-float/2addr";
        case 0xcb: return "add-double/2addr"; case 0xcc: return "sub-double/2addr"; case 0xcd: return "mul-double/2addr";
        case 0xce: return "div-double/2addr"; case 0xcf: return "rem-double/2addr";
        case 0xd0: return "add-int/lit16"; case 0xd1: return "rsub-int"; case 0xd2: return "mul-int/lit16";
        case 0xd3: return "div-int/lit16"; case 0xd4: return "rem-int/lit16"; case 0xd5: return "and-int/lit16";
        case 0xd6: return "or-int/lit16"; case 0xd7: return "xor-int/lit16"; case 0xd8: return "add-int/lit8";
        case 0xd9: return "rsub-int/lit8"; case 0xda: return "mul-int/lit8"; case 0xdb: return "div-int/lit8";
        case 0xdc: return "rem-int/lit8"; case 0xdd: return "and-int/lit8"; case 0xde: return "or-int/lit8";
        case 0xdf: return "xor-int/lit8"; case 0xe0: return "shl-int/lit8"; case 0xe1: return "shr-int/lit8";
        case 0xe2: return "ushr-int/lit8"; case 0xfa: return "invoke-polymorphic";
        case 0xfb: return "invoke-polymorphic/range"; case 0xfc: return "invoke-custom";
        case 0xfd: return "invoke-custom/range"; case 0xfe: return "const-method-handle";
        case 0xff: return "const-method-type";
        default: return "reserved";
    }
}

workspace_result_t<dex_container_info_t>
detect_dex_container(const byte_provider_t& provider, const cancellation_token_t& cancel) {
    if (cancel.stop_requested())
        return workspace_result_t<dex_container_info_t>::failure(dex_stop_error(cancel, "dex.detect"));
    auto prefix = read_prefix(provider, 8, cancel);
    if (!prefix)
        return workspace_result_t<dex_container_info_t>::failure(prefix.error());
    return detect_from_prefix(prefix.value());
}

workspace_result_t<bool>
is_dex_file(const byte_provider_t& provider, const cancellation_token_t& cancel) {
    auto detected = detect_dex_container(provider, cancel);
    if (!detected)
        return workspace_result_t<bool>::failure(detected.error());
    return workspace_result_t<bool>::success(detected.value().kind == dex_container_kind_t::dex ||
                                              detected.value().kind == dex_container_kind_t::compact_dex);
}

workspace_result_t<bool>
is_oat_file(const byte_provider_t& provider, const cancellation_token_t& cancel) {
    auto detected = detect_dex_container(provider, cancel);
    if (!detected)
        return workspace_result_t<bool>::failure(detected.error());
    return workspace_result_t<bool>::success(detected.value().kind == dex_container_kind_t::oat);
}

workspace_result_t<bool>
is_vdex_file(const byte_provider_t& provider, const cancellation_token_t& cancel) {
    auto detected = detect_dex_container(provider, cancel);
    if (!detected)
        return workspace_result_t<bool>::failure(detected.error());
    return workspace_result_t<bool>::success(detected.value().kind == dex_container_kind_t::vdex);
}

workspace_result_t<dex_image_t>
parse_dex_image(const byte_provider_t& provider, const dex_parse_limits_t& limits,
                const cancellation_token_t& cancel) {
    try {
        if (limits.max_file_size < kDexHeaderSize || limits.max_container_scan_bytes < 8 ||
            limits.max_embedded_dex_files == 0 || limits.max_string_ids == 0 || limits.max_type_ids == 0 ||
            limits.max_proto_ids == 0 || limits.max_field_ids == 0 || limits.max_method_ids == 0 ||
            limits.max_class_defs == 0 || limits.max_instruction_records_per_method == 0 ||
            limits.max_total_instruction_records == 0 || limits.max_string_bytes == 0 ||
            limits.max_single_string_bytes == 0)
            return workspace_result_t<dex_image_t>::failure(dex_error(
                workspace_error_code_t::invalid_argument, "DEX parser limits are invalid", "dex.limits"));
        auto detected = detect_dex_container(provider, cancel);
        if (!detected)
            return workspace_result_t<dex_image_t>::failure(detected.error());
        switch (detected.value().kind) {
            case dex_container_kind_t::dex:
                return parse_dex_at(provider, 0, detected.take_value(), limits, cancel);
            case dex_container_kind_t::oat:
            case dex_container_kind_t::vdex:
                return parse_container(provider, detected.take_value(), limits, cancel);
            case dex_container_kind_t::compact_dex:
                return workspace_result_t<dex_image_t>::failure(dex_error(
                    workspace_error_code_t::unsupported_format,
                    "compact DEX detection succeeded but compact DEX decoding is unavailable", "dex.detect"));
            case dex_container_kind_t::unknown:
                return workspace_result_t<dex_image_t>::failure(dex_error(
                    workspace_error_code_t::unsupported_format, "input is not DEX, OAT, or VDEX", "dex.detect"));
        }
        return workspace_result_t<dex_image_t>::failure(dex_error(
            workspace_error_code_t::unsupported_format, "unknown DEX container kind", "dex.detect"));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<dex_image_t>::failure(dex_error(
            workspace_error_code_t::limit_exceeded, "DEX parser allocation failed", "dex.allocate"));
    }
}

workspace_result_t<dex_image_t>
parse_dex_image(const byte_provider_t& provider, const cancellation_token_t& cancel) {
    return parse_dex_image(provider, dex_parse_limits_t{}, cancel);
}

workspace_result_t<workspace_image_t>
parse_dex(const byte_provider_t& provider, const dex_parse_limits_t& limits,
          const cancellation_token_t& cancel) {
    auto parsed = parse_dex_image(provider, limits, cancel);
    if (!parsed)
        return workspace_result_t<workspace_image_t>::failure(parsed.error());
    return workspace_result_t<workspace_image_t>::success(std::move(parsed.value().normalized));
}

workspace_result_t<workspace_image_t>
parse_dex(const byte_provider_t& provider, const cancellation_token_t& cancel) {
    return parse_dex(provider, dex_parse_limits_t{}, cancel);
}

}
