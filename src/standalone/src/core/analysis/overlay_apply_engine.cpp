#include "overlay_apply_engine.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace aida::analysis {

namespace {

using json = nlohmann::json;

constexpr std::uint8_t k_last_overlay_operation_ordinal =
    static_cast<std::uint8_t>(overlay_operation_kind_v9_t::reanalysis);

bool has_nonzero_bytes(const std::array<std::uint8_t, 32>& value) noexcept
{
    return std::any_of(value.begin(), value.end(), [](std::uint8_t byte) { return byte != 0; });
}

bool valid_architecture(overlay_architecture_v9_t architecture) noexcept
{
    return architecture >= overlay_architecture_v9_t::x86 &&
        architecture <= overlay_architecture_v9_t::dalvik;
}

bool valid_utf8(const std::string& value) noexcept
{
    const auto continuation = [&value](std::size_t index) noexcept {
        return index < value.size() &&
            (static_cast<unsigned char>(value[index]) & 0xc0U) == 0x80U;
    };
    for (std::size_t index = 0; index < value.size();) {
        const auto byte = static_cast<unsigned char>(value[index]);
        if (byte <= 0x7fU) {
            if (byte == 0)
                return false;
            ++index;
            continue;
        }
        if (byte >= 0xc2U && byte <= 0xdfU) {
            if (!continuation(index + 1))
                return false;
            index += 2;
            continue;
        }
        if (byte == 0xe0U) {
            if (index + 2 >= value.size() ||
                static_cast<unsigned char>(value[index + 1]) < 0xa0U ||
                static_cast<unsigned char>(value[index + 1]) > 0xbfU || !continuation(index + 2))
                return false;
            index += 3;
            continue;
        }
        if ((byte >= 0xe1U && byte <= 0xecU) || (byte >= 0xeeU && byte <= 0xefU)) {
            if (!continuation(index + 1) || !continuation(index + 2))
                return false;
            index += 3;
            continue;
        }
        if (byte == 0xedU) {
            if (index + 2 >= value.size() ||
                static_cast<unsigned char>(value[index + 1]) < 0x80U ||
                static_cast<unsigned char>(value[index + 1]) > 0x9fU || !continuation(index + 2))
                return false;
            index += 3;
            continue;
        }
        if (byte == 0xf0U) {
            if (index + 3 >= value.size() ||
                static_cast<unsigned char>(value[index + 1]) < 0x90U ||
                static_cast<unsigned char>(value[index + 1]) > 0xbfU ||
                !continuation(index + 2) || !continuation(index + 3))
                return false;
            index += 4;
            continue;
        }
        if (byte >= 0xf1U && byte <= 0xf3U) {
            if (!continuation(index + 1) || !continuation(index + 2) || !continuation(index + 3))
                return false;
            index += 4;
            continue;
        }
        if (byte == 0xf4U) {
            if (index + 3 >= value.size() ||
                static_cast<unsigned char>(value[index + 1]) < 0x80U ||
                static_cast<unsigned char>(value[index + 1]) > 0x8fU ||
                !continuation(index + 2) || !continuation(index + 3))
                return false;
            index += 4;
            continue;
        }
        return false;
    }
    return true;
}

bool bounded_string(const std::string& value, std::size_t limit) noexcept
{
    return value.size() <= limit && valid_utf8(value);
}

bool add_size(std::size_t& total, std::size_t value, std::size_t limit) noexcept
{
    if (value > limit - total)
        return false;
    total += value;
    return true;
}

bool range_is_empty(const overlay_static_range_v9_t& range) noexcept
{
    return range.offset == 0 && range.size == 0;
}

bool range_is_valid_for_target(const overlay_static_range_v9_t& range,
                               const overlay_target_identity_v9_t& target) noexcept
{
    return range.size != 0 && range.offset < target.image_size &&
        range.size <= target.image_size - range.offset;
}

bool operation_requires_range(overlay_operation_kind_v9_t kind) noexcept
{
    return kind != overlay_operation_kind_v9_t::type_declaration &&
        kind != overlay_operation_kind_v9_t::enum_definition;
}

overlay_operation_kind_v9_t entity_domain(overlay_operation_kind_v9_t kind) noexcept
{
    if (kind == overlay_operation_kind_v9_t::comment_update)
        return overlay_operation_kind_v9_t::comment;
    if (kind == overlay_operation_kind_v9_t::delete_stack_variable)
        return overlay_operation_kind_v9_t::stack_variable;
    if (kind == overlay_operation_kind_v9_t::type_update)
        return overlay_operation_kind_v9_t::type_application;
    if (kind == overlay_operation_kind_v9_t::assembly_patch ||
        kind == overlay_operation_kind_v9_t::integer_patch)
        return overlay_operation_kind_v9_t::byte_patch;
    return kind;
}

overlay_entity_key_v9_t make_entity_key(const overlay_operation_v9_t& operation)
{
    overlay_entity_key_v9_t key;
    key.domain = entity_domain(operation.kind);
    key.range = operation.range;
    if (key.domain == overlay_operation_kind_v9_t::comment ||
        key.domain == overlay_operation_kind_v9_t::stack_variable ||
        key.domain == overlay_operation_kind_v9_t::type_application ||
        key.domain == overlay_operation_kind_v9_t::byte_patch)
        key.range.size = 0;
    key.stack_offset = operation.payload.stack_offset;
    switch (operation.kind) {
    case overlay_operation_kind_v9_t::type_declaration:
    case overlay_operation_kind_v9_t::enum_definition:
        key.qualifier = operation.payload.name;
        break;
    case overlay_operation_kind_v9_t::stack_variable:
    case overlay_operation_kind_v9_t::delete_stack_variable:
        key.qualifier = operation.payload.name;
        break;
    case overlay_operation_kind_v9_t::type_application:
    case overlay_operation_kind_v9_t::type_update:
        key.qualifier = operation.payload.variable.empty()
            ? operation.payload.name : operation.payload.variable;
        break;
    default:
        break;
    }
    return key;
}

bool valid_integer_type(const std::string& value, std::size_t& size) noexcept
{
    static constexpr std::array<std::pair<const char*, std::size_t>, 24> values{{
        {"i8", 1}, {"u8", 1}, {"i8le", 1}, {"u8le", 1},
        {"i8be", 1}, {"u8be", 1}, {"i16", 2}, {"u16", 2},
        {"i16le", 2}, {"u16le", 2}, {"i16be", 2}, {"u16be", 2},
        {"i32", 4}, {"u32", 4}, {"i32le", 4}, {"u32le", 4},
        {"i32be", 4}, {"u32be", 4}, {"i64", 8}, {"u64", 8},
        {"i64le", 8}, {"u64le", 8}, {"i64be", 8}, {"u64be", 8}
    }};
    for (const auto& item : values) {
        if (value == item.first) {
            size = item.second;
            return true;
        }
    }
    return false;
}

bool integer_patch_matches_value(const overlay_payload_v9_t& payload,
                                 std::size_t byte_size) noexcept
{
    if (payload.integer_value.empty() || payload.bytes.size() != byte_size)
        return false;
    std::size_t cursor = 0;
    bool negative = false;
    if (payload.integer_value[cursor] == '+' ||
        payload.integer_value[cursor] == '-') {
        negative = payload.integer_value[cursor] == '-';
        ++cursor;
    }
    int base = 10;
    if (payload.integer_value.size() - cursor >= 2 &&
        payload.integer_value[cursor] == '0') {
        const char prefix = payload.integer_value[cursor + 1];
        if (prefix == 'x' || prefix == 'X') {
            base = 16;
            cursor += 2;
        } else if (prefix == 'b' || prefix == 'B') {
            base = 2;
            cursor += 2;
        } else if (prefix == 'o' || prefix == 'O') {
            base = 8;
            cursor += 2;
        }
    }
    if (cursor == payload.integer_value.size())
        return false;
    std::uint64_t magnitude = 0;
    const auto parsed = std::from_chars(
        payload.integer_value.data() + cursor,
        payload.integer_value.data() + payload.integer_value.size(),
        magnitude, base);
    if (parsed.ec != std::errc{} ||
        parsed.ptr != payload.integer_value.data() + payload.integer_value.size())
        return false;
    const bool signed_type = payload.integer_type.front() == 'i';
    if (negative && !signed_type)
        return false;
    const auto bits = static_cast<unsigned>(byte_size * 8);
    const auto mask = bits == 64
        ? (std::numeric_limits<std::uint64_t>::max)()
        : (std::uint64_t{1} << bits) - 1;
    std::uint64_t encoded = magnitude;
    if (signed_type) {
        const auto sign_limit = std::uint64_t{1} << (bits - 1);
        if (negative) {
            if (magnitude == 0 || magnitude > sign_limit)
                return false;
            encoded = (std::uint64_t{0} - magnitude) & mask;
        } else if (magnitude >= sign_limit) {
            return false;
        }
    } else if (magnitude > mask) {
        return false;
    }
    const bool big_endian = payload.integer_type.size() >= 2 &&
        payload.integer_type.compare(payload.integer_type.size() - 2, 2, "be") == 0;
    for (std::size_t index = 0; index < byte_size; ++index) {
        const auto shift = static_cast<unsigned>(
            (big_endian ? byte_size - index - 1 : index) * 8);
        if (payload.bytes[index] != static_cast<std::uint8_t>(encoded >> shift))
            return false;
    }
    return true;
}

bool valid_operation_kind(overlay_operation_kind_v9_t kind) noexcept
{
    return static_cast<std::uint8_t>(kind) <= k_last_overlay_operation_ordinal;
}

bool nonempty_for_update(const overlay_operation_v9_t& operation) noexcept
{
    const auto& payload = operation.payload;
    switch (operation.kind) {
    case overlay_operation_kind_v9_t::comment:
    case overlay_operation_kind_v9_t::comment_update:
        return !payload.text.empty();
    case overlay_operation_kind_v9_t::name:
    case overlay_operation_kind_v9_t::bookmark:
        return !payload.name.empty();
    case overlay_operation_kind_v9_t::type_declaration:
    case overlay_operation_kind_v9_t::enum_definition:
        return !payload.name.empty() && !payload.type.empty();
    case overlay_operation_kind_v9_t::stack_variable:
        return !payload.name.empty() && !payload.type.empty();
    case overlay_operation_kind_v9_t::delete_stack_variable:
        return !payload.name.empty();
    case overlay_operation_kind_v9_t::type_application:
    case overlay_operation_kind_v9_t::type_update:
        return !payload.type.empty() && (!payload.name.empty() || !payload.variable.empty());
    case overlay_operation_kind_v9_t::byte_patch:
        return !payload.bytes.empty();
    case overlay_operation_kind_v9_t::assembly_patch:
        return !payload.bytes.empty() && !payload.assembly.empty();
    case overlay_operation_kind_v9_t::integer_patch:
        return !payload.bytes.empty() && !payload.integer_type.empty() &&
            !payload.integer_value.empty();
    case overlay_operation_kind_v9_t::define_function:
    case overlay_operation_kind_v9_t::define_code:
    case overlay_operation_kind_v9_t::define_data:
    case overlay_operation_kind_v9_t::undefine:
    case overlay_operation_kind_v9_t::reanalysis:
        return true;
    }
    return false;
}

bool canonical_patch_provenance(const overlay_operation_v9_t& operation) noexcept
{
    const auto& payload = operation.payload;
    switch (operation.kind) {
    case overlay_operation_kind_v9_t::byte_patch:
        return payload.assembly.empty() && payload.integer_type.empty() &&
               payload.integer_value.empty();
    case overlay_operation_kind_v9_t::assembly_patch:
        return !payload.assembly.empty() && payload.integer_type.empty() &&
               payload.integer_value.empty();
    case overlay_operation_kind_v9_t::integer_patch:
        return payload.assembly.empty() && !payload.integer_type.empty() &&
               !payload.integer_value.empty();
    default:
        return true;
    }
}

overlay_apply_code_v9_t validate_operation(const overlay_operation_v9_t& operation,
                                           const overlay_target_identity_v9_t& target,
                                           const overlay_apply_limits_v9_t& limits,
                                           std::size_t& patch_bytes,
                                           std::size_t& payload_bytes) noexcept
{
    if (!valid_operation_kind(operation.kind))
        return overlay_apply_code_v9_t::invalid_operation;
    const auto& payload = operation.payload;
    if (!bounded_string(payload.name, limits.max_text_bytes) ||
        !bounded_string(payload.text, limits.max_text_bytes) ||
        !bounded_string(payload.type, limits.max_type_bytes) ||
        !bounded_string(payload.variable, limits.max_text_bytes) ||
        !bounded_string(payload.signature, limits.max_type_bytes) ||
        !bounded_string(payload.assembly, limits.max_text_bytes) ||
        !bounded_string(payload.integer_type, limits.max_text_bytes) ||
        !bounded_string(payload.integer_value, limits.max_text_bytes))
        return overlay_apply_code_v9_t::limit_exceeded;
    const std::array<std::size_t, 9> payload_sizes{{
        payload.name.size(), payload.text.size(), payload.type.size(), payload.variable.size(),
        payload.signature.size(), payload.assembly.size(), payload.integer_type.size(),
        payload.integer_value.size(), payload.bytes.size()
    }};
    for (const auto size : payload_sizes) {
        if (!add_size(payload_bytes, size, limits.max_transaction_payload_bytes))
            return overlay_apply_code_v9_t::limit_exceeded;
    }
    if (operation_requires_range(operation.kind)) {
        if (!range_is_valid_for_target(operation.range, target))
            return overlay_apply_code_v9_t::invalid_operation;
    } else if (!range_is_empty(operation.range)) {
        return overlay_apply_code_v9_t::invalid_operation;
    }
    if (operation.remove) {
        if ((operation.kind == overlay_operation_kind_v9_t::type_declaration ||
             operation.kind == overlay_operation_kind_v9_t::enum_definition ||
             operation.kind == overlay_operation_kind_v9_t::stack_variable ||
             operation.kind == overlay_operation_kind_v9_t::delete_stack_variable) &&
            payload.name.empty())
            return overlay_apply_code_v9_t::invalid_operation;
        if ((operation.kind == overlay_operation_kind_v9_t::type_application ||
             operation.kind == overlay_operation_kind_v9_t::type_update) &&
            payload.name.empty() && payload.variable.empty())
            return overlay_apply_code_v9_t::invalid_operation;
        return overlay_apply_code_v9_t::ok;
    }
    if (!nonempty_for_update(operation))
        return overlay_apply_code_v9_t::invalid_operation;
    const bool patch = operation.kind == overlay_operation_kind_v9_t::byte_patch ||
        operation.kind == overlay_operation_kind_v9_t::assembly_patch ||
        operation.kind == overlay_operation_kind_v9_t::integer_patch;
    if (!patch)
        return overlay_apply_code_v9_t::ok;
    if (!canonical_patch_provenance(operation))
        return overlay_apply_code_v9_t::invalid_operation;
    if (payload.bytes.size() > limits.max_patch_bytes_per_operation ||
        payload.bytes.size() > limits.max_patch_bytes_per_transaction - patch_bytes)
        return overlay_apply_code_v9_t::limit_exceeded;
    if (operation.range.size != payload.bytes.size())
        return overlay_apply_code_v9_t::invalid_operation;
    patch_bytes += payload.bytes.size();
    if (operation.kind == overlay_operation_kind_v9_t::integer_patch) {
        std::size_t integer_size = 0;
        if (!valid_integer_type(payload.integer_type, integer_size) ||
            integer_size != payload.bytes.size() ||
            !integer_patch_matches_value(payload, integer_size))
            return overlay_apply_code_v9_t::invalid_operation;
    }
    return overlay_apply_code_v9_t::ok;
}

overlay_apply_result_v9_t result_for(const overlay_static_state_v9_t& state,
                                     overlay_apply_code_v9_t code) noexcept
{
    overlay_apply_result_v9_t result;
    result.code = code;
    result.revision = state.revision;
    result.history_cursor = state.history_cursor;
    return result;
}

overlay_apply_code_v9_t validate_target(const overlay_target_identity_v9_t& expected,
                                        const overlay_static_state_v9_t& state) noexcept
{
    if (!expected.valid() || !state.target.valid())
        return overlay_apply_code_v9_t::invalid_target;
    if (expected.kind != overlay_target_kind_v9_t::static_image ||
        state.target.kind != overlay_target_kind_v9_t::static_image)
        return overlay_apply_code_v9_t::static_target_required;
    if (expected != state.target || expected.generation != state.target.generation)
        return overlay_apply_code_v9_t::stale_generation;
    return overlay_apply_code_v9_t::ok;
}

bool coherent_state(const overlay_static_state_v9_t& state) noexcept
{
    return state.target.valid() && state.target.kind == overlay_target_kind_v9_t::static_image &&
        state.next_transaction_id != 0 && state.history_epoch != 0 &&
        state.history_cursor <= state.history.size();
}

void apply_change(std::map<overlay_entity_key_v9_t, overlay_payload_v9_t>& items,
                  const overlay_entity_key_v9_t& entity,
                  const std::optional<overlay_payload_v9_t>& value)
{
    if (value)
        items[entity] = *value;
    else
        items.erase(entity);
}

overlay_change_v9_t inverse_change(const overlay_change_v9_t& change)
{
    overlay_change_v9_t result = change;
    std::swap(result.before_kind, result.after_kind);
    std::swap(result.before, result.after);
    return result;
}

template <std::size_t Size>
std::string fixed_hex(const std::array<std::uint8_t, Size>& bytes)
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string result(Size * 2, '0');
    for (std::size_t index = 0; index < Size; ++index) {
        result[index * 2] = digits[bytes[index] >> 4];
        result[index * 2 + 1] = digits[bytes[index] & 0x0f];
    }
    return result;
}

std::string byte_hex(const std::vector<std::uint8_t>& bytes)
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string result(bytes.size() * 2, '0');
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        result[index * 2] = digits[bytes[index] >> 4];
        result[index * 2 + 1] = digits[bytes[index] & 0x0f];
    }
    return result;
}

int hex_nibble(char value) noexcept
{
    if (value >= '0' && value <= '9')
        return value - '0';
    if (value >= 'a' && value <= 'f')
        return value - 'a' + 10;
    return -1;
}

template <std::size_t Size>
bool parse_fixed_hex(const std::string& value, std::array<std::uint8_t, Size>& bytes) noexcept
{
    if (value.size() != Size * 2)
        return false;
    for (std::size_t index = 0; index < Size; ++index) {
        const int high = hex_nibble(value[index * 2]);
        const int low = hex_nibble(value[index * 2 + 1]);
        if (high < 0 || low < 0)
            return false;
        bytes[index] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return true;
}

bool parse_byte_hex(const std::string& value, std::vector<std::uint8_t>& bytes)
{
    if ((value.size() & 1U) != 0)
        return false;
    bytes.resize(value.size() / 2);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        const int high = hex_nibble(value[index * 2]);
        const int low = hex_nibble(value[index * 2 + 1]);
        if (high < 0 || low < 0)
            return false;
        bytes[index] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return true;
}

template <typename Integer>
bool parse_decimal(const json& value, Integer& result) noexcept
{
    if (!value.is_string())
        return false;
    const auto& text = value.get_ref<const std::string&>();
    if (text.empty())
        return false;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result, 10);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}

template <std::size_t Size>
bool exact_fields(const json& value, const std::array<const char*, Size>& fields) noexcept
{
    if (!value.is_object() || value.size() != Size)
        return false;
    return std::all_of(fields.begin(), fields.end(),
                       [&](const char* field) { return value.contains(field); });
}

json target_json_v9(const overlay_target_identity_v9_t& target)
{
    return json{{"address_width", target.address_width},
                {"architecture", static_cast<std::uint8_t>(target.architecture)},
                {"generation", std::to_string(target.generation)},
                {"image_base", std::to_string(target.image_base)},
                {"image_hash", fixed_hex(target.image_hash)},
                {"image_size", std::to_string(target.image_size)},
                {"kind", static_cast<std::uint8_t>(target.kind)},
                {"provenance_hash", fixed_hex(target.provenance_hash)},
                {"reserved", target.reserved},
                {"schema", k_overlay_journal_v9_schema}};
}

std::optional<overlay_target_identity_v9_t> parse_target_json_v9(const json& value) noexcept
{
    try {
        static constexpr std::array<const char*, 10> fields{{
            "address_width", "architecture", "generation", "image_base", "image_hash",
            "image_size", "kind", "provenance_hash", "reserved", "schema"
        }};
        if (!exact_fields(value, fields) || !value["schema"].is_number_unsigned() ||
            value["schema"].get<std::uint32_t>() != k_overlay_journal_v9_schema ||
            !value["address_width"].is_number_unsigned() ||
            !value["architecture"].is_number_unsigned() ||
            !value["kind"].is_number_unsigned() || !value["reserved"].is_number_unsigned() ||
            !value["image_hash"].is_string() || !value["provenance_hash"].is_string())
            return std::nullopt;
        overlay_target_identity_v9_t target;
        const auto address_width = value["address_width"].get<unsigned>();
        const auto architecture = value["architecture"].get<unsigned>();
        const auto kind = value["kind"].get<unsigned>();
        const auto reserved = value["reserved"].get<unsigned>();
        if (address_width > (std::numeric_limits<std::uint8_t>::max)() ||
            architecture > static_cast<unsigned>(overlay_architecture_v9_t::dalvik) ||
            kind > static_cast<unsigned>(overlay_target_kind_v9_t::live_image) ||
            reserved > (std::numeric_limits<std::uint8_t>::max)())
            return std::nullopt;
        target.address_width = static_cast<std::uint8_t>(address_width);
        target.architecture = static_cast<overlay_architecture_v9_t>(architecture);
        target.kind = static_cast<overlay_target_kind_v9_t>(kind);
        target.reserved = static_cast<std::uint8_t>(reserved);
        if (!parse_decimal(value["generation"], target.generation) ||
            !parse_decimal(value["image_base"], target.image_base) ||
            !parse_decimal(value["image_size"], target.image_size) ||
            !parse_fixed_hex(value["image_hash"].get_ref<const std::string&>(), target.image_hash) ||
            !parse_fixed_hex(value["provenance_hash"].get_ref<const std::string&>(),
                             target.provenance_hash) || !target.valid())
            return std::nullopt;
        return target;
    } catch (...) {
        return std::nullopt;
    }
}

json operation_json_v9(const overlay_operation_v9_t& operation)
{
    return json{{"kind", static_cast<std::uint8_t>(operation.kind)},
                {"payload", json{{"assembly", operation.payload.assembly},
                                 {"bytes", byte_hex(operation.payload.bytes)},
                                 {"integer_type", operation.payload.integer_type},
                                 {"integer_value", operation.payload.integer_value},
                                 {"name", operation.payload.name},
                                 {"reanalysis_flags", operation.payload.reanalysis_flags},
                                 {"signature", operation.payload.signature},
                                 {"stack_offset", std::to_string(operation.payload.stack_offset)},
                                 {"text", operation.payload.text},
                                 {"type", operation.payload.type},
                                 {"variable", operation.payload.variable}}},
                {"range", json{{"offset", std::to_string(operation.range.offset)},
                               {"size", std::to_string(operation.range.size)}}},
                {"remove", operation.remove}};
}

std::optional<overlay_operation_v9_t> parse_operation_json_v9(
    const json& value, const overlay_target_identity_v9_t& target) noexcept
{
    try {
        static constexpr std::array<const char*, 4> fields{{"kind", "payload", "range", "remove"}};
        static constexpr std::array<const char*, 2> range_fields{{"offset", "size"}};
        static constexpr std::array<const char*, 11> payload_fields{{
            "assembly", "bytes", "integer_type", "integer_value", "name", "reanalysis_flags",
            "signature", "stack_offset", "text", "type", "variable"
        }};
        if (!exact_fields(value, fields) || !value["kind"].is_number_unsigned() ||
            !value["remove"].is_boolean() || !exact_fields(value["range"], range_fields) ||
            !exact_fields(value["payload"], payload_fields))
            return std::nullopt;
        const auto ordinal = value["kind"].get<unsigned>();
        if (ordinal > k_last_overlay_operation_ordinal)
            return std::nullopt;
        const auto& payload = value["payload"];
        for (const char* field : {"assembly", "bytes", "integer_type", "integer_value", "name",
                                  "signature", "stack_offset", "text", "type", "variable"}) {
            if (!payload[field].is_string())
                return std::nullopt;
        }
        if (!payload["reanalysis_flags"].is_number_unsigned())
            return std::nullopt;
        overlay_operation_v9_t operation;
        operation.kind = static_cast<overlay_operation_kind_v9_t>(ordinal);
        operation.remove = value["remove"].get<bool>();
        if (!parse_decimal(value["range"]["offset"], operation.range.offset) ||
            !parse_decimal(value["range"]["size"], operation.range.size) ||
            !parse_decimal(payload["stack_offset"], operation.payload.stack_offset))
            return std::nullopt;
        operation.payload.assembly = payload["assembly"].get<std::string>();
        operation.payload.integer_type = payload["integer_type"].get<std::string>();
        operation.payload.integer_value = payload["integer_value"].get<std::string>();
        operation.payload.name = payload["name"].get<std::string>();
        operation.payload.reanalysis_flags = payload["reanalysis_flags"].get<std::uint32_t>();
        operation.payload.signature = payload["signature"].get<std::string>();
        operation.payload.text = payload["text"].get<std::string>();
        operation.payload.type = payload["type"].get<std::string>();
        operation.payload.variable = payload["variable"].get<std::string>();
        if (!parse_byte_hex(payload["bytes"].get_ref<const std::string&>(),
                            operation.payload.bytes))
            return std::nullopt;
        std::size_t patch_bytes = 0;
        std::size_t payload_bytes = 0;
        if (validate_operation(operation, target, {}, patch_bytes, payload_bytes) !=
            overlay_apply_code_v9_t::ok)
            return std::nullopt;
        return operation;
    } catch (...) {
        return std::nullopt;
    }
}

}

std::optional<overlay_operation_kind_v9_t>
overlay_operation_kind_from_ordinal(std::uint8_t ordinal) noexcept
{
    if (ordinal > k_last_overlay_operation_ordinal)
        return std::nullopt;
    return static_cast<overlay_operation_kind_v9_t>(ordinal);
}

bool overlay_target_identity_v9_t::valid() const noexcept
{
    const bool static_target = kind == overlay_target_kind_v9_t::static_image;
    const bool known_target = static_target || kind == overlay_target_kind_v9_t::live_image;
    const bool supported_width = address_width == 4 || address_width == 8;
    return known_target && valid_architecture(architecture) && supported_width && reserved == 0 &&
        has_nonzero_bytes(image_hash) && has_nonzero_bytes(provenance_hash) && image_size != 0 &&
        image_base <= (std::numeric_limits<std::uint64_t>::max)() - image_size && generation != 0 &&
        generation != (std::numeric_limits<std::uint64_t>::max)();
}

bool overlay_target_identity_v9_t::operator==(const overlay_target_identity_v9_t& other) const noexcept
{
    return image_hash == other.image_hash && provenance_hash == other.provenance_hash &&
        image_base == other.image_base && image_size == other.image_size &&
        generation == other.generation && kind == other.kind && architecture == other.architecture &&
        address_width == other.address_width && reserved == other.reserved;
}

bool overlay_target_identity_v9_t::operator!=(const overlay_target_identity_v9_t& other) const noexcept
{
    return !(*this == other);
}

bool overlay_static_range_v9_t::operator==(const overlay_static_range_v9_t& other) const noexcept
{
    return offset == other.offset && size == other.size;
}

bool overlay_static_range_v9_t::operator!=(const overlay_static_range_v9_t& other) const noexcept
{
    return !(*this == other);
}

bool overlay_payload_v9_t::operator==(const overlay_payload_v9_t& other) const noexcept
{
    return name == other.name && text == other.text && type == other.type &&
        variable == other.variable && signature == other.signature && assembly == other.assembly &&
        integer_type == other.integer_type && integer_value == other.integer_value &&
        bytes == other.bytes && reanalysis_flags == other.reanalysis_flags &&
        stack_offset == other.stack_offset;
}

bool overlay_payload_v9_t::operator!=(const overlay_payload_v9_t& other) const noexcept
{
    return !(*this == other);
}

bool overlay_operation_v9_t::operator==(const overlay_operation_v9_t& other) const noexcept
{
    return kind == other.kind && range == other.range && payload == other.payload &&
        remove == other.remove;
}

bool overlay_operation_v9_t::operator!=(const overlay_operation_v9_t& other) const noexcept
{
    return !(*this == other);
}

bool overlay_operation_record_v9_t::operator==(
    const overlay_operation_record_v9_t& other) const noexcept
{
    return target == other.target && operation == other.operation;
}

bool overlay_operation_record_v9_t::operator!=(
    const overlay_operation_record_v9_t& other) const noexcept
{
    return !(*this == other);
}

bool overlay_entity_key_v9_t::operator==(const overlay_entity_key_v9_t& other) const noexcept
{
    return domain == other.domain && range == other.range && stack_offset == other.stack_offset &&
        qualifier == other.qualifier;
}

bool overlay_entity_key_v9_t::operator!=(const overlay_entity_key_v9_t& other) const noexcept
{
    return !(*this == other);
}

bool overlay_entity_key_v9_t::operator<(const overlay_entity_key_v9_t& other) const noexcept
{
    return std::tie(domain, range.offset, range.size, stack_offset, qualifier) <
        std::tie(other.domain, other.range.offset, other.range.size, other.stack_offset, other.qualifier);
}

overlay_entity_key_v9_t
overlay_entity_key_for_operation_v9(const overlay_operation_v9_t& operation)
{
    return make_entity_key(operation);
}

std::optional<overlay_operation_kind_v9_t> overlay_operation_kind_for_item_v9(
    const overlay_entity_key_v9_t& entity,
    const overlay_payload_v9_t& payload) noexcept
{
    if (!valid_operation_kind(entity.domain))
        return std::nullopt;
    if (entity.domain != overlay_operation_kind_v9_t::byte_patch)
        return entity.domain;
    if (entity.range.size != 0 || payload.bytes.empty())
        return std::nullopt;
    const bool has_assembly = !payload.assembly.empty();
    const bool has_integer_type = !payload.integer_type.empty();
    const bool has_integer_value = !payload.integer_value.empty();
    if (has_integer_type != has_integer_value ||
        (has_assembly && has_integer_type))
        return std::nullopt;
    if (has_assembly)
        return overlay_operation_kind_v9_t::assembly_patch;
    if (has_integer_type) {
        std::size_t integer_size = 0;
        if (!valid_integer_type(payload.integer_type, integer_size) ||
            integer_size != payload.bytes.size() ||
            !integer_patch_matches_value(payload, integer_size))
            return std::nullopt;
        return overlay_operation_kind_v9_t::integer_patch;
    }
    return overlay_operation_kind_v9_t::byte_patch;
}

std::string serialize_overlay_target_identity_v9(
    const overlay_target_identity_v9_t& target)
{
    if (!target.valid())
        throw std::invalid_argument("overlay v9 target identity is invalid");
    return target_json_v9(target).dump();
}

std::optional<overlay_target_identity_v9_t>
deserialize_overlay_target_identity_v9(std::string_view serialized) noexcept
{
    try {
        auto value = json::parse(serialized.begin(), serialized.end(), nullptr, false);
        if (value.is_discarded())
            return std::nullopt;
        return parse_target_json_v9(value);
    } catch (...) {
        return std::nullopt;
    }
}

std::string serialize_overlay_operation_record_v9(
    const overlay_operation_record_v9_t& record)
{
    if (!record.target.valid())
        throw std::invalid_argument("overlay v9 operation target is invalid");
    std::size_t patch_bytes = 0;
    std::size_t payload_bytes = 0;
    if (validate_operation(record.operation, record.target, {}, patch_bytes, payload_bytes) !=
        overlay_apply_code_v9_t::ok)
        throw std::invalid_argument("overlay v9 operation is invalid");
    return json{{"operation", operation_json_v9(record.operation)},
                {"schema", k_overlay_journal_v9_schema},
                {"target", target_json_v9(record.target)}}.dump();
}

std::optional<overlay_operation_record_v9_t>
deserialize_overlay_operation_record_v9(std::string_view serialized) noexcept
{
    try {
        auto value = json::parse(serialized.begin(), serialized.end(), nullptr, false);
        static constexpr std::array<const char*, 3> fields{{"operation", "schema", "target"}};
        if (value.is_discarded() || !exact_fields(value, fields) ||
            !value["schema"].is_number_unsigned() ||
            value["schema"].get<std::uint32_t>() != k_overlay_journal_v9_schema)
            return std::nullopt;
        auto target = parse_target_json_v9(value["target"]);
        if (!target)
            return std::nullopt;
        auto operation = parse_operation_json_v9(value["operation"], *target);
        if (!operation)
            return std::nullopt;
        return overlay_operation_record_v9_t{*target, std::move(*operation)};
    } catch (...) {
        return std::nullopt;
    }
}

overlay_apply_result_v9_t overlay_apply_engine_v9_t::initialize(
    overlay_static_state_v9_t& state, const overlay_target_identity_v9_t& target) noexcept
{
    if (!target.valid())
        return result_for(state, overlay_apply_code_v9_t::invalid_target);
    if (target.kind != overlay_target_kind_v9_t::static_image)
        return result_for(state, overlay_apply_code_v9_t::static_target_required);
    if (state.revision != 0 || state.next_transaction_id != 1 || state.history_cursor != 0 ||
        state.history_epoch != 1 || !state.items.empty() || !state.history.empty() || state.target.valid())
        return result_for(state, overlay_apply_code_v9_t::state_already_initialized);
    state.target = target;
    return result_for(state, overlay_apply_code_v9_t::ok);
}

overlay_apply_result_v9_t overlay_apply_engine_v9_t::apply(
    overlay_static_state_v9_t& state, const overlay_transaction_v9_t& transaction,
    const overlay_apply_limits_v9_t& limits) noexcept
{
    try {
        if (!coherent_state(state))
            return result_for(state, overlay_apply_code_v9_t::state_not_initialized);
        const auto target_code = validate_target(transaction.target, state);
        if (target_code != overlay_apply_code_v9_t::ok)
            return result_for(state, target_code);
        if (transaction.expected_revision != state.revision)
            return result_for(state, overlay_apply_code_v9_t::revision_conflict);
        if (state.revision == (std::numeric_limits<std::uint64_t>::max)())
            return result_for(state, overlay_apply_code_v9_t::revision_overflow);
        if (state.next_transaction_id == (std::numeric_limits<std::uint64_t>::max)())
            return result_for(state, overlay_apply_code_v9_t::transaction_overflow);
        if (transaction.operations.empty() ||
            transaction.operations.size() > limits.max_operations_per_transaction)
            return result_for(state, overlay_apply_code_v9_t::limit_exceeded);
        if (state.history.size() > limits.max_history_entries ||
            state.history_cursor > state.history.size())
            return result_for(state, overlay_apply_code_v9_t::history_overflow);

        std::size_t patch_bytes = 0;
        std::size_t payload_bytes = 0;
        std::vector<overlay_change_v9_t> changes;
        changes.reserve(transaction.operations.size());
        std::map<overlay_entity_key_v9_t, bool> entities;
        for (const auto& operation : transaction.operations) {
            const auto operation_code = validate_operation(operation, state.target, limits,
                                                           patch_bytes, payload_bytes);
            if (operation_code != overlay_apply_code_v9_t::ok)
                return result_for(state, operation_code);
            const auto entity = make_entity_key(operation);
            if (!entities.emplace(entity, true).second)
                return result_for(state, overlay_apply_code_v9_t::duplicate_entity);
            const auto current = state.items.find(entity);
            overlay_change_v9_t change;
            change.entity = entity;
            if (current != state.items.end()) {
                const auto current_kind = overlay_operation_kind_for_item_v9(
                    current->first, current->second);
                if (!current_kind)
                    return result_for(state, overlay_apply_code_v9_t::invalid_operation);
                change.before_kind = *current_kind;
                change.before = current->second;
            }
            if (!operation.remove) {
                change.after_kind = operation.kind;
                change.after = operation.payload;
            }
            if (operation.remove && !change.before)
                return result_for(state, overlay_apply_code_v9_t::invalid_operation);
            change.operation_kind = operation.kind;
            changes.push_back(std::move(change));
        }

        const bool truncates_redo = state.history_cursor != state.history.size();
        if ((truncates_redo && state.history_epoch == (std::numeric_limits<std::uint64_t>::max)()) ||
            state.history_cursor >= limits.max_history_entries)
            return result_for(state, overlay_apply_code_v9_t::history_overflow);

        auto next_items = state.items;
        for (const auto& change : changes)
            apply_change(next_items, change.entity, change.after);
        auto next_history = state.history;
        if (truncates_redo)
            next_history.erase(next_history.begin() + static_cast<std::ptrdiff_t>(state.history_cursor),
                               next_history.end());
        overlay_history_entry_v9_t entry;
        entry.target = state.target;
        entry.transaction_id = state.next_transaction_id;
        entry.generation = state.target.generation;
        entry.originating_revision = state.revision + 1;
        entry.changes = changes;
        next_history.push_back(std::move(entry));

        overlay_apply_result_v9_t result;
        result.code = overlay_apply_code_v9_t::ok;
        result.revision = state.revision + 1;
        result.transaction_id = state.next_transaction_id;
        result.history_cursor = static_cast<std::uint64_t>(next_history.size());
        result.changes = changes;
        state.items = std::move(next_items);
        state.history = std::move(next_history);
        state.revision = result.revision;
        state.next_transaction_id += 1;
        state.history_cursor = result.history_cursor;
        if (truncates_redo)
            state.history_epoch += 1;
        return result;
    } catch (...) {
        return result_for(state, overlay_apply_code_v9_t::storage_failure);
    }
}

overlay_apply_result_v9_t overlay_apply_engine_v9_t::undo(
    overlay_static_state_v9_t& state, const overlay_target_identity_v9_t& target,
    std::uint64_t expected_revision) noexcept
{
    try {
        if (!coherent_state(state))
            return result_for(state, overlay_apply_code_v9_t::state_not_initialized);
        const auto target_code = validate_target(target, state);
        if (target_code != overlay_apply_code_v9_t::ok)
            return result_for(state, target_code);
        if (expected_revision != state.revision)
            return result_for(state, overlay_apply_code_v9_t::revision_conflict);
        if (state.revision == (std::numeric_limits<std::uint64_t>::max)())
            return result_for(state, overlay_apply_code_v9_t::revision_overflow);
        if (state.history_cursor == 0)
            return result_for(state, overlay_apply_code_v9_t::no_undo);
        const auto& entry = state.history[static_cast<std::size_t>(state.history_cursor - 1)];
        if (entry.target != state.target || entry.generation != state.target.generation)
            return result_for(state, overlay_apply_code_v9_t::stale_generation);

        auto next_items = state.items;
        std::vector<overlay_change_v9_t> changes;
        changes.reserve(entry.changes.size());
        for (auto iterator = entry.changes.rbegin(); iterator != entry.changes.rend(); ++iterator) {
            apply_change(next_items, iterator->entity, iterator->before);
            changes.push_back(inverse_change(*iterator));
        }
        overlay_apply_result_v9_t result;
        result.code = overlay_apply_code_v9_t::ok;
        result.revision = state.revision + 1;
        result.transaction_id = entry.transaction_id;
        result.history_cursor = state.history_cursor - 1;
        result.changes = std::move(changes);
        state.items = std::move(next_items);
        state.revision = result.revision;
        state.history_cursor = result.history_cursor;
        return result;
    } catch (...) {
        return result_for(state, overlay_apply_code_v9_t::storage_failure);
    }
}

overlay_apply_result_v9_t overlay_apply_engine_v9_t::redo(
    overlay_static_state_v9_t& state, const overlay_target_identity_v9_t& target,
    std::uint64_t expected_revision) noexcept
{
    try {
        if (!coherent_state(state))
            return result_for(state, overlay_apply_code_v9_t::state_not_initialized);
        const auto target_code = validate_target(target, state);
        if (target_code != overlay_apply_code_v9_t::ok)
            return result_for(state, target_code);
        if (expected_revision != state.revision)
            return result_for(state, overlay_apply_code_v9_t::revision_conflict);
        if (state.revision == (std::numeric_limits<std::uint64_t>::max)())
            return result_for(state, overlay_apply_code_v9_t::revision_overflow);
        if (state.history_cursor == state.history.size())
            return result_for(state, overlay_apply_code_v9_t::no_redo);
        const auto& entry = state.history[static_cast<std::size_t>(state.history_cursor)];
        if (entry.target != state.target || entry.generation != state.target.generation)
            return result_for(state, overlay_apply_code_v9_t::stale_generation);

        auto next_items = state.items;
        for (const auto& change : entry.changes)
            apply_change(next_items, change.entity, change.after);
        overlay_apply_result_v9_t result;
        result.code = overlay_apply_code_v9_t::ok;
        result.revision = state.revision + 1;
        result.transaction_id = entry.transaction_id;
        result.history_cursor = state.history_cursor + 1;
        result.changes = entry.changes;
        state.items = std::move(next_items);
        state.revision = result.revision;
        state.history_cursor = result.history_cursor;
        return result;
    } catch (...) {
        return result_for(state, overlay_apply_code_v9_t::storage_failure);
    }
}

}
