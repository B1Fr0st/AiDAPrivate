#include "classfile_parser.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <limits>
#include <string_view>
#include <utility>

namespace aida::analysis {
namespace {

workspace_error_t parse_error(std::string message, std::uint64_t offset = 0,
                              std::uint64_t size = 0) {
    auto error = make_workspace_error(workspace_error_code_t::malformed_pe,
                                      std::move(message), "classfile_parse");
    error.offset = offset;
    error.size = size;
    return error;
}

workspace_error_t limit_error(std::string message, std::uint64_t value,
                              std::uint64_t limit) {
    auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                                      std::move(message), "classfile_parse");
    error.details.emplace_back("value", std::to_string(value));
    error.details.emplace_back("limit", std::to_string(limit));
    return error;
}

workspace_error_t stop_error(const cancellation_token_t& cancel) {
    auto error = make_workspace_error(cancel.deadline_exceeded()
                                          ? workspace_error_code_t::deadline_exceeded
                                          : workspace_error_code_t::cancelled,
                                      cancel.deadline_exceeded()
                                          ? "classfile parsing deadline exceeded"
                                          : "classfile parsing cancelled",
                                      "classfile_parse");
    error.deadline = cancel.deadline_exceeded();
    error.cancellation = !error.deadline;
    return error;
}

bool stopped(const cancellation_token_t& cancel) noexcept {
    return cancel.cancellation_requested() || cancel.deadline_exceeded();
}

std::uint16_t be16(const std::uint8_t* value) noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(value[0]) << 8) | value[1]);
}

std::uint32_t be32(const std::uint8_t* value) noexcept {
    return (static_cast<std::uint32_t>(value[0]) << 24) |
           (static_cast<std::uint32_t>(value[1]) << 16) |
           (static_cast<std::uint32_t>(value[2]) << 8) |
           static_cast<std::uint32_t>(value[3]);
}

bool add_within(std::uint64_t offset, std::uint64_t length,
                std::uint64_t limit) noexcept {
    return offset <= limit && length <= limit - offset;
}

struct reader_t {
    const std::uint8_t* bytes = nullptr;
    std::uint64_t size = 0;
    std::uint64_t offset = 0;

    workspace_result_t<void> require(std::uint64_t length) const {
        if (!add_within(offset, length, size))
            return workspace_result_t<void>::failure(
                parse_error("classfile structure exceeds input bounds", offset, length));
        return workspace_result_t<void>::success();
    }

    workspace_result_t<std::uint8_t> u1() {
        auto result = require(1);
        if (!result)
            return workspace_result_t<std::uint8_t>::failure(std::move(result.error()));
        return workspace_result_t<std::uint8_t>::success(bytes[offset++]);
    }

    workspace_result_t<std::uint16_t> u2() {
        auto result = require(2);
        if (!result)
            return workspace_result_t<std::uint16_t>::failure(std::move(result.error()));
        const auto value = be16(bytes + offset);
        offset += 2;
        return workspace_result_t<std::uint16_t>::success(value);
    }

    workspace_result_t<std::uint32_t> u4() {
        auto result = require(4);
        if (!result)
            return workspace_result_t<std::uint32_t>::failure(std::move(result.error()));
        const auto value = be32(bytes + offset);
        offset += 4;
        return workspace_result_t<std::uint32_t>::success(value);
    }

    workspace_result_t<std::vector<std::uint8_t>> take(std::uint64_t length) {
        auto result = require(length);
        if (!result)
            return workspace_result_t<std::vector<std::uint8_t>>::failure(std::move(result.error()));
        std::vector<std::uint8_t> value(bytes + offset, bytes + offset + static_cast<std::size_t>(length));
        offset += length;
        return workspace_result_t<std::vector<std::uint8_t>>::success(std::move(value));
    }
};

struct cp_entry_t {
    jvm_constant_tag_t tag = jvm_constant_tag_t::invalid;
    std::uint64_t file_offset = 0;
    std::string utf8;
    std::uint32_t scalar = 0;
    std::uint64_t wide_scalar = 0;
    std::uint16_t first = 0;
    std::uint16_t second = 0;
    std::uint8_t reference_kind = 0;
    std::uint16_t bootstrap_index = 0;
    bool double_slot = false;
    bool valid = false;
};

struct parse_budget_t {
    std::uint64_t attributes = 0;
    std::uint64_t attribute_bytes = 0;
    std::uint64_t code_bytes = 0;
    std::uint64_t lines = 0;
    std::uint64_t locals = 0;
};

const cp_entry_t* cp_at(const std::vector<cp_entry_t>& pool, std::uint16_t index) noexcept {
    if (index == 0 || index >= pool.size() || !pool[index].valid)
        return nullptr;
    return &pool[index];
}

const std::string* cp_utf8(const std::vector<cp_entry_t>& pool, std::uint16_t index) noexcept {
    const auto* entry = cp_at(pool, index);
    return entry != nullptr && entry->tag == jvm_constant_tag_t::utf8 ? &entry->utf8 : nullptr;
}

workspace_result_t<const cp_entry_t*> cp_required(
    const std::vector<cp_entry_t>& pool, std::uint16_t index, jvm_constant_tag_t tag,
    std::string_view context, std::uint64_t offset) {
    const auto* entry = cp_at(pool, index);
    if (entry == nullptr || entry->tag != tag)
        return workspace_result_t<const cp_entry_t*>::failure(parse_error(
            std::string(context) + " references an invalid constant-pool entry", offset, 2));
    return workspace_result_t<const cp_entry_t*>::success(entry);
}

workspace_result_t<std::string> decode_modified_utf8(const std::uint8_t* bytes,
                                                      std::uint16_t length,
                                                      std::uint64_t file_offset) {
    std::vector<std::uint16_t> units;
    units.reserve(length);
    std::uint64_t offset = 0;
    while (offset < length) {
        const auto first = bytes[offset++];
        if (first >= 1 && first <= 0x7f) {
            units.push_back(first);
            continue;
        }
        if ((first & 0xe0u) == 0xc0u) {
            if (offset >= length)
                return workspace_result_t<std::string>::failure(
                    parse_error("truncated modified UTF-8 sequence", file_offset + offset - 1, 1));
            const auto second = bytes[offset++];
            if ((second & 0xc0u) != 0x80u ||
                (first == 0xc0u && second != 0x80u) || first == 0xc1u)
                return workspace_result_t<std::string>::failure(
                    parse_error("invalid modified UTF-8 two-byte sequence", file_offset + offset - 2, 2));
            units.push_back(static_cast<std::uint16_t>(((first & 0x1fu) << 6) | (second & 0x3fu)));
            continue;
        }
        if ((first & 0xf0u) == 0xe0u) {
            if (length - offset < 2)
                return workspace_result_t<std::string>::failure(
                    parse_error("truncated modified UTF-8 sequence", file_offset + offset - 1, 1));
            const auto second = bytes[offset++];
            const auto third = bytes[offset++];
            if ((second & 0xc0u) != 0x80u || (third & 0xc0u) != 0x80u ||
                (first == 0xe0u && second < 0xa0u))
                return workspace_result_t<std::string>::failure(
                    parse_error("invalid modified UTF-8 three-byte sequence", file_offset + offset - 3, 3));
            units.push_back(static_cast<std::uint16_t>(((first & 0x0fu) << 12) |
                                                       ((second & 0x3fu) << 6) |
                                                       (third & 0x3fu)));
            continue;
        }
        return workspace_result_t<std::string>::failure(
            parse_error("invalid modified UTF-8 leading byte", file_offset + offset - 1, 1));
    }

    std::string value;
    value.reserve(length);
    for (std::size_t i = 0; i < units.size(); ++i) {
        std::uint32_t code_point = units[i];
        if (code_point >= 0xd800u && code_point <= 0xdbffu) {
            if (i + 1 >= units.size() || units[i + 1] < 0xdc00u || units[i + 1] > 0xdfffu)
                return workspace_result_t<std::string>::failure(
                    parse_error("unpaired modified UTF-8 high surrogate", file_offset, length));
            code_point = 0x10000u + ((code_point - 0xd800u) << 10) + (units[++i] - 0xdc00u);
        } else if (code_point >= 0xdc00u && code_point <= 0xdfffu) {
            return workspace_result_t<std::string>::failure(
                parse_error("unpaired modified UTF-8 low surrogate", file_offset, length));
        }
        if (code_point <= 0x7fu) {
            value.push_back(static_cast<char>(code_point));
        } else if (code_point <= 0x7ffu) {
            value.push_back(static_cast<char>(0xc0u | (code_point >> 6)));
            value.push_back(static_cast<char>(0x80u | (code_point & 0x3fu)));
        } else if (code_point <= 0xffffu) {
            value.push_back(static_cast<char>(0xe0u | (code_point >> 12)));
            value.push_back(static_cast<char>(0x80u | ((code_point >> 6) & 0x3fu)));
            value.push_back(static_cast<char>(0x80u | (code_point & 0x3fu)));
        } else {
            value.push_back(static_cast<char>(0xf0u | (code_point >> 18)));
            value.push_back(static_cast<char>(0x80u | ((code_point >> 12) & 0x3fu)));
            value.push_back(static_cast<char>(0x80u | ((code_point >> 6) & 0x3fu)));
            value.push_back(static_cast<char>(0x80u | (code_point & 0x3fu)));
        }
    }
    return workspace_result_t<std::string>::success(std::move(value));
}

bool cp_tag_available(jvm_constant_tag_t tag, std::uint16_t major) noexcept {
    if (tag == jvm_constant_tag_t::method_handle || tag == jvm_constant_tag_t::method_type ||
        tag == jvm_constant_tag_t::invoke_dynamic)
        return major >= 51;
    if (tag == jvm_constant_tag_t::module_ref || tag == jvm_constant_tag_t::package_ref)
        return major >= 53;
    if (tag == jvm_constant_tag_t::dynamic)
        return major >= 55;
    return true;
}

workspace_result_t<std::vector<cp_entry_t>> parse_constant_pool(
    reader_t& reader, std::uint16_t count, std::uint16_t major,
    const classfile_parse_limits_t& limits, const cancellation_token_t& cancel) {
    if (count == 0 || count > limits.max_constant_pool_entries)
        return workspace_result_t<std::vector<cp_entry_t>>::failure(
            limit_error("constant-pool count exceeds limit", count, limits.max_constant_pool_entries));
    std::vector<cp_entry_t> pool(count);
    for (std::uint32_t index = 1; index < count; ++index) {
        if (stopped(cancel))
            return workspace_result_t<std::vector<cp_entry_t>>::failure(stop_error(cancel));
        const auto entry_offset = reader.offset;
        auto tag_result = reader.u1();
        if (!tag_result)
            return workspace_result_t<std::vector<cp_entry_t>>::failure(std::move(tag_result.error()));
        cp_entry_t entry;
        entry.file_offset = entry_offset;
        entry.valid = true;
        const auto assign_one = [&](jvm_constant_tag_t tag) { entry.tag = tag; };
        switch (tag_result.value()) {
            case 1: {
                assign_one(jvm_constant_tag_t::utf8);
                auto length = reader.u2();
                if (!length)
                    return workspace_result_t<std::vector<cp_entry_t>>::failure(std::move(length.error()));
                if (length.value() > limits.max_utf8_length)
                    return workspace_result_t<std::vector<cp_entry_t>>::failure(
                        limit_error("modified UTF-8 constant exceeds limit", length.value(), limits.max_utf8_length));
                auto bytes = reader.take(length.value());
                if (!bytes)
                    return workspace_result_t<std::vector<cp_entry_t>>::failure(std::move(bytes.error()));
                auto decoded = decode_modified_utf8(bytes.value().data(), length.value(), reader.offset - length.value());
                if (!decoded)
                    return workspace_result_t<std::vector<cp_entry_t>>::failure(std::move(decoded.error()));
                entry.utf8 = decoded.take_value();
                break;
            }
            case 3: case 4: {
                assign_one(tag_result.value() == 3 ? jvm_constant_tag_t::integer : jvm_constant_tag_t::float_);
                auto value = reader.u4();
                if (!value)
                    return workspace_result_t<std::vector<cp_entry_t>>::failure(std::move(value.error()));
                entry.scalar = value.value();
                break;
            }
            case 5: case 6: {
                if (index + 1 >= count)
                    return workspace_result_t<std::vector<cp_entry_t>>::failure(
                        parse_error("wide constant-pool entry has no reserved slot", entry_offset, 1));
                assign_one(tag_result.value() == 5 ? jvm_constant_tag_t::long_ : jvm_constant_tag_t::double_);
                auto high = reader.u4();
                auto low = reader.u4();
                if (!high)
                    return workspace_result_t<std::vector<cp_entry_t>>::failure(std::move(high.error()));
                if (!low)
                    return workspace_result_t<std::vector<cp_entry_t>>::failure(std::move(low.error()));
                entry.wide_scalar = (static_cast<std::uint64_t>(high.value()) << 32) | low.value();
                entry.double_slot = true;
                break;
            }
            case 7: case 8: case 16: case 19: case 20: {
                const auto tag = tag_result.value() == 7 ? jvm_constant_tag_t::class_ref :
                                 tag_result.value() == 8 ? jvm_constant_tag_t::string_ref :
                                 tag_result.value() == 16 ? jvm_constant_tag_t::method_type :
                                 tag_result.value() == 19 ? jvm_constant_tag_t::module_ref :
                                 jvm_constant_tag_t::package_ref;
                assign_one(tag);
                auto reference = reader.u2();
                if (!reference)
                    return workspace_result_t<std::vector<cp_entry_t>>::failure(std::move(reference.error()));
                entry.first = reference.value();
                break;
            }
            case 9: case 10: case 11: case 12: {
                assign_one(tag_result.value() == 9 ? jvm_constant_tag_t::fieldref :
                           tag_result.value() == 10 ? jvm_constant_tag_t::methodref :
                           tag_result.value() == 11 ? jvm_constant_tag_t::interface_methodref :
                           jvm_constant_tag_t::name_and_type);
                auto first = reader.u2();
                auto second = reader.u2();
                if (!first)
                    return workspace_result_t<std::vector<cp_entry_t>>::failure(std::move(first.error()));
                if (!second)
                    return workspace_result_t<std::vector<cp_entry_t>>::failure(std::move(second.error()));
                entry.first = first.value();
                entry.second = second.value();
                break;
            }
            case 15: {
                assign_one(jvm_constant_tag_t::method_handle);
                auto kind = reader.u1();
                auto reference = reader.u2();
                if (!kind)
                    return workspace_result_t<std::vector<cp_entry_t>>::failure(std::move(kind.error()));
                if (!reference)
                    return workspace_result_t<std::vector<cp_entry_t>>::failure(std::move(reference.error()));
                entry.reference_kind = kind.value();
                entry.first = reference.value();
                break;
            }
            case 17: case 18: {
                assign_one(tag_result.value() == 17 ? jvm_constant_tag_t::dynamic : jvm_constant_tag_t::invoke_dynamic);
                auto bootstrap = reader.u2();
                auto descriptor = reader.u2();
                if (!bootstrap)
                    return workspace_result_t<std::vector<cp_entry_t>>::failure(std::move(bootstrap.error()));
                if (!descriptor)
                    return workspace_result_t<std::vector<cp_entry_t>>::failure(std::move(descriptor.error()));
                entry.bootstrap_index = bootstrap.value();
                entry.first = descriptor.value();
                break;
            }
            default:
                return workspace_result_t<std::vector<cp_entry_t>>::failure(
                    parse_error("unsupported constant-pool tag", entry_offset, 1));
        }
        if (!cp_tag_available(entry.tag, major))
            return workspace_result_t<std::vector<cp_entry_t>>::failure(
                parse_error("constant-pool tag is unavailable for classfile version", entry_offset, 1));
        pool[index] = std::move(entry);
        if (pool[index].double_slot)
            ++index;
    }
    return workspace_result_t<std::vector<cp_entry_t>>::success(std::move(pool));
}

workspace_result_t<void> validate_constant_pool(const std::vector<cp_entry_t>& pool,
                                                 std::uint16_t major) {
    for (std::size_t index = 1; index < pool.size(); ++index) {
        const auto& entry = pool[index];
        if (!entry.valid)
            continue;
        const auto required = [&](std::uint16_t reference, jvm_constant_tag_t tag,
                                  std::string_view field) -> workspace_result_t<void> {
            auto result = cp_required(pool, reference, tag, field, entry.file_offset);
            if (!result)
                return workspace_result_t<void>::failure(std::move(result.error()));
            return workspace_result_t<void>::success();
        };
        workspace_result_t<void> result = workspace_result_t<void>::success();
        switch (entry.tag) {
            case jvm_constant_tag_t::class_ref:
            case jvm_constant_tag_t::string_ref:
            case jvm_constant_tag_t::method_type:
            case jvm_constant_tag_t::module_ref:
            case jvm_constant_tag_t::package_ref:
                result = required(entry.first, jvm_constant_tag_t::utf8, "constant-pool entry");
                break;
            case jvm_constant_tag_t::fieldref:
            case jvm_constant_tag_t::methodref:
            case jvm_constant_tag_t::interface_methodref:
                result = required(entry.first, jvm_constant_tag_t::class_ref, "member reference");
                if (result)
                    result = required(entry.second, jvm_constant_tag_t::name_and_type, "member reference");
                break;
            case jvm_constant_tag_t::name_and_type:
                result = required(entry.first, jvm_constant_tag_t::utf8, "name-and-type entry");
                if (result)
                    result = required(entry.second, jvm_constant_tag_t::utf8, "name-and-type entry");
                break;
            case jvm_constant_tag_t::method_handle: {
                if (entry.reference_kind < 1 || entry.reference_kind > 9)
                    return workspace_result_t<void>::failure(parse_error(
                        "method-handle reference kind is invalid", entry.file_offset, 1));
                const auto* reference = cp_at(pool, entry.first);
                const bool field = entry.reference_kind >= 1 && entry.reference_kind <= 4;
                const bool method = reference != nullptr &&
                    (reference->tag == jvm_constant_tag_t::methodref ||
                     (entry.reference_kind >= 6 && entry.reference_kind <= 7 &&
                      reference->tag == jvm_constant_tag_t::interface_methodref) ||
                     (entry.reference_kind == 9 && reference->tag == jvm_constant_tag_t::interface_methodref));
                if (reference == nullptr ||
                    (field && reference->tag != jvm_constant_tag_t::fieldref) ||
                    (!field && !method) ||
                    (entry.reference_kind == 8 && reference->tag != jvm_constant_tag_t::methodref) ||
                    (entry.reference_kind == 6 && reference->tag == jvm_constant_tag_t::interface_methodref && major < 52))
                    return workspace_result_t<void>::failure(parse_error(
                        "method-handle target has an invalid constant-pool tag", entry.file_offset, 3));
                break;
            }
            case jvm_constant_tag_t::dynamic:
            case jvm_constant_tag_t::invoke_dynamic:
                result = required(entry.first, jvm_constant_tag_t::name_and_type, "dynamic constant entry");
                break;
            default:
                break;
        }
        if (!result)
            return result;
    }
    return workspace_result_t<void>::success();
}

bool valid_unqualified_name(std::string_view value, bool method) noexcept {
    if (value.empty())
        return false;
    if (method && (value == "<init>" || value == "<clinit>"))
        return true;
    return value.find_first_of("./;[<>") == std::string_view::npos;
}

bool parse_field_descriptor(std::string_view descriptor, std::size_t& offset,
                            bool allow_void) noexcept {
    if (offset >= descriptor.size())
        return false;
    const auto value = descriptor[offset++];
    if (value == 'V')
        return allow_void;
    if (value == 'B' || value == 'C' || value == 'D' || value == 'F' || value == 'I' ||
        value == 'J' || value == 'S' || value == 'Z')
        return true;
    if (value == '[')
        return parse_field_descriptor(descriptor, offset, false);
    if (value != 'L')
        return false;
    const auto start = offset;
    while (offset < descriptor.size() && descriptor[offset] != ';') {
        const auto character = descriptor[offset++];
        if (character == '.' || character == '[' || character == '\0')
            return false;
    }
    if (offset == start || offset >= descriptor.size())
        return false;
    ++offset;
    return true;
}

bool valid_field_descriptor(std::string_view descriptor) noexcept {
    std::size_t offset = 0;
    return parse_field_descriptor(descriptor, offset, false) && offset == descriptor.size();
}

bool valid_method_descriptor(std::string_view descriptor) noexcept {
    if (descriptor.size() < 3 || descriptor.front() != '(')
        return false;
    std::size_t offset = 1;
    while (offset < descriptor.size() && descriptor[offset] != ')') {
        if (!parse_field_descriptor(descriptor, offset, false))
            return false;
    }
    if (offset >= descriptor.size() || descriptor[offset++] != ')')
        return false;
    return parse_field_descriptor(descriptor, offset, true) && offset == descriptor.size();
}

workspace_result_t<jvm_attribute_t> parse_attribute(
    reader_t& reader, const std::vector<cp_entry_t>& pool, parse_budget_t& budget,
    const classfile_parse_limits_t& limits) {
    const auto attribute_offset = reader.offset;
    auto name_index = reader.u2();
    auto length = reader.u4();
    if (!name_index)
        return workspace_result_t<jvm_attribute_t>::failure(std::move(name_index.error()));
    if (!length)
        return workspace_result_t<jvm_attribute_t>::failure(std::move(length.error()));
    const auto* name = cp_utf8(pool, name_index.value());
    if (name == nullptr)
        return workspace_result_t<jvm_attribute_t>::failure(
            parse_error("attribute name index does not reference UTF-8", attribute_offset, 2));
    if (length.value() > limits.max_attribute_size ||
        budget.attribute_bytes > limits.max_total_attribute_bytes - length.value())
        return workspace_result_t<jvm_attribute_t>::failure(limit_error(
            "attribute payload budget exceeded", length.value(), limits.max_total_attribute_bytes));
    if (++budget.attributes > limits.max_total_attributes)
        return workspace_result_t<jvm_attribute_t>::failure(limit_error(
            "total attribute count exceeds limit", budget.attributes, limits.max_total_attributes));
    auto data = reader.take(length.value());
    if (!data)
        return workspace_result_t<jvm_attribute_t>::failure(std::move(data.error()));
    budget.attribute_bytes += length.value();
    jvm_attribute_t attribute;
    attribute.name = *name;
    attribute.name_index = name_index.value();
    attribute.offset = reader.offset - length.value();
    attribute.length = length.value();
    attribute.raw_data = data.take_value();
    return workspace_result_t<jvm_attribute_t>::success(std::move(attribute));
}

workspace_result_t<std::vector<jvm_attribute_t>> parse_attributes(
    reader_t& reader, const std::vector<cp_entry_t>& pool, parse_budget_t& budget,
    const classfile_parse_limits_t& limits, const cancellation_token_t& cancel) {
    auto count = reader.u2();
    if (!count)
        return workspace_result_t<std::vector<jvm_attribute_t>>::failure(std::move(count.error()));
    if (count.value() > limits.max_attributes)
        return workspace_result_t<std::vector<jvm_attribute_t>>::failure(limit_error(
            "attribute-table count exceeds limit", count.value(), limits.max_attributes));
    std::vector<jvm_attribute_t> attributes;
    attributes.reserve(count.value());
    for (std::uint16_t index = 0; index < count.value(); ++index) {
        if (stopped(cancel))
            return workspace_result_t<std::vector<jvm_attribute_t>>::failure(stop_error(cancel));
        auto attribute = parse_attribute(reader, pool, budget, limits);
        if (!attribute)
            return workspace_result_t<std::vector<jvm_attribute_t>>::failure(std::move(attribute.error()));
        attributes.push_back(attribute.take_value());
    }
    return workspace_result_t<std::vector<jvm_attribute_t>>::success(std::move(attributes));
}

const std::array<const char*, 203> opcode_names = {{
    "nop","aconst_null","iconst_m1","iconst_0","iconst_1","iconst_2","iconst_3","iconst_4","iconst_5","lconst_0","lconst_1","fconst_0","fconst_1","fconst_2","dconst_0","dconst_1","bipush","sipush","ldc","ldc_w","ldc2_w","iload","lload","fload","dload","aload","iload_0","iload_1","iload_2","iload_3","lload_0","lload_1","lload_2","lload_3","fload_0","fload_1","fload_2","fload_3","dload_0","dload_1","dload_2","dload_3","aload_0","aload_1","aload_2","aload_3","iaload","laload","faload","daload","aaload","baload","caload","saload","istore","lstore","fstore","dstore","astore","istore_0","istore_1","istore_2","istore_3","lstore_0","lstore_1","lstore_2","lstore_3","fstore_0","fstore_1","fstore_2","fstore_3","dstore_0","dstore_1","dstore_2","dstore_3","astore_0","astore_1","astore_2","astore_3","iastore","lastore","fastore","dastore","aastore","bastore","castore","sastore","pop","pop2","dup","dup_x1","dup_x2","dup2","dup2_x1","dup2_x2","swap","iadd","ladd","fadd","dadd","isub","lsub","fsub","dsub","imul","lmul","fmul","dmul","idiv","ldiv","fdiv","ddiv","irem","lrem","frem","drem","ineg","lneg","fneg","dneg","ishl","lshl","ishr","lshr","iushr","lushr","iand","land","ior","lor","ixor","lxor","iinc","i2l","i2f","i2d","l2i","l2f","l2d","f2i","f2l","f2d","d2i","d2l","d2f","i2b","i2c","i2s","lcmp","fcmpl","fcmpg","dcmpl","dcmpg","ifeq","ifne","iflt","ifge","ifgt","ifle","if_icmpeq","if_icmpne","if_icmplt","if_icmpge","if_icmpgt","if_icmple","if_acmpeq","if_acmpne","goto","jsr","ret","tableswitch","lookupswitch","ireturn","lreturn","freturn","dreturn","areturn","return","getstatic","putstatic","getfield","putfield","invokevirtual","invokespecial","invokestatic","invokeinterface","invokedynamic","new","newarray","anewarray","arraylength","athrow","checkcast","instanceof","monitorenter","monitorexit","wide","multianewarray","ifnull","ifnonnull","goto_w","jsr_w","breakpoint"
}};

bool valid_opcode(std::uint8_t opcode) noexcept {
    return opcode < 0xca;
}

workspace_result_t<void> validate_constant_operand(const std::vector<cp_entry_t>& pool,
                                                    std::uint16_t index,
                                                    std::uint8_t opcode,
                                                    std::uint64_t offset) {
    const auto* entry = cp_at(pool, index);
    if (entry == nullptr)
        return workspace_result_t<void>::failure(parse_error(
            "bytecode references an invalid constant-pool entry", offset, 2));
    const auto is = [&](jvm_constant_tag_t tag) { return entry->tag == tag; };
    bool valid = true;
    switch (opcode) {
        case 0x12: case 0x13:
            valid = is(jvm_constant_tag_t::integer) || is(jvm_constant_tag_t::float_) ||
                    is(jvm_constant_tag_t::string_ref) || is(jvm_constant_tag_t::class_ref) ||
                    is(jvm_constant_tag_t::method_type) || is(jvm_constant_tag_t::method_handle) ||
                    is(jvm_constant_tag_t::dynamic);
            break;
        case 0x14:
            valid = is(jvm_constant_tag_t::long_) || is(jvm_constant_tag_t::double_) ||
                    is(jvm_constant_tag_t::dynamic);
            break;
        case 0xb2: case 0xb3: case 0xb4: case 0xb5:
            valid = is(jvm_constant_tag_t::fieldref);
            break;
        case 0xb6:
            valid = is(jvm_constant_tag_t::methodref);
            break;
        case 0xb7: case 0xb8:
            valid = is(jvm_constant_tag_t::methodref) || is(jvm_constant_tag_t::interface_methodref);
            break;
        case 0xb9:
            valid = is(jvm_constant_tag_t::interface_methodref);
            break;
        case 0xba:
            valid = is(jvm_constant_tag_t::invoke_dynamic);
            break;
        case 0xbb: case 0xbd: case 0xc0: case 0xc1: case 0xc5:
            valid = is(jvm_constant_tag_t::class_ref);
            break;
        default:
            break;
    }
    if (!valid)
        return workspace_result_t<void>::failure(parse_error(
            "bytecode constant-pool tag is incompatible with opcode", offset, 2));
    return workspace_result_t<void>::success();
}

workspace_result_t<std::vector<jvm_bytecode_instruction_t>> parse_bytecode(
    const std::vector<std::uint8_t>& code, std::uint64_t code_offset,
    const std::vector<cp_entry_t>& pool, const classfile_parse_limits_t& limits,
    const cancellation_token_t& cancel) {
    std::vector<jvm_bytecode_instruction_t> instructions;
    std::uint64_t offset = 0;
    const auto require = [&](std::uint64_t start, std::uint64_t length) {
        return add_within(start, length, code.size());
    };
    const auto branch_target = [&](std::uint64_t start, std::int32_t displacement)
        -> workspace_result_t<std::uint64_t> {
        const auto target = static_cast<std::int64_t>(start) + displacement;
        if (target < 0 || static_cast<std::uint64_t>(target) >= code.size())
            return workspace_result_t<std::uint64_t>::failure(parse_error(
                "bytecode branch target exceeds Code attribute", code_offset + start, 1));
        return workspace_result_t<std::uint64_t>::success(static_cast<std::uint64_t>(target));
    };
    while (offset < code.size()) {
        if ((instructions.size() & 0xffu) == 0 && stopped(cancel))
            return workspace_result_t<std::vector<jvm_bytecode_instruction_t>>::failure(stop_error(cancel));
        if (instructions.size() >= limits.max_instructions_per_method)
            return workspace_result_t<std::vector<jvm_bytecode_instruction_t>>::failure(limit_error(
                "bytecode instruction count exceeds limit", instructions.size(), limits.max_instructions_per_method));
        const auto opcode = code[static_cast<std::size_t>(offset)];
        if (!valid_opcode(opcode))
            return workspace_result_t<std::vector<jvm_bytecode_instruction_t>>::failure(
                parse_error("reserved or implementation-dependent JVM opcode", code_offset + offset, 1));
        jvm_bytecode_instruction_t instruction;
        instruction.offset = offset;
        instruction.opcode = opcode;
        instruction.mnemonic = opcode_names[opcode];
        auto fixed = [&](std::uint64_t length) -> workspace_result_t<void> {
            if (!require(offset, length))
                return workspace_result_t<void>::failure(parse_error(
                    "bytecode instruction is truncated", code_offset + offset, length));
            instruction.length = static_cast<std::uint32_t>(length);
            if (length > 1)
                instruction.operands.assign(code.begin() + static_cast<std::ptrdiff_t>(offset + 1),
                                            code.begin() + static_cast<std::ptrdiff_t>(offset + length));
            return workspace_result_t<void>::success();
        };
        workspace_result_t<void> result = workspace_result_t<void>::success();
        switch (opcode) {
            case 0x10: case 0x11:
                result = fixed(opcode == 0x10 ? 2 : 3);
                break;
            case 0x12:
                result = fixed(2);
                if (result)
                    instruction.constant_pool_index = code[static_cast<std::size_t>(offset + 1)];
                break;
            case 0x13: case 0x14:
                result = fixed(3);
                if (result)
                    instruction.constant_pool_index = be16(code.data() + offset + 1);
                break;
            case 0x15: case 0x16: case 0x17: case 0x18: case 0x19:
            case 0x36: case 0x37: case 0x38: case 0x39: case 0x3a: case 0xa9:
                result = fixed(2);
                if (result)
                    instruction.local_variable_index = code[static_cast<std::size_t>(offset + 1)];
                break;
            case 0x84:
                result = fixed(3);
                if (result) {
                    instruction.local_variable_index = code[static_cast<std::size_t>(offset + 1)];
                    instruction.increment = static_cast<std::int8_t>(code[static_cast<std::size_t>(offset + 2)]);
                }
                break;
            case 0x99: case 0x9a: case 0x9b: case 0x9c: case 0x9d: case 0x9e:
            case 0x9f: case 0xa0: case 0xa1: case 0xa2: case 0xa3: case 0xa4:
            case 0xa5: case 0xa6: case 0xa7: case 0xa8: case 0xc6: case 0xc7:
                result = fixed(3);
                if (result) {
                    const auto displacement = static_cast<std::int32_t>(static_cast<std::int16_t>(be16(code.data() + offset + 1)));
                    auto target = branch_target(offset, displacement);
                    if (!target)
                        result = workspace_result_t<void>::failure(std::move(target.error()));
                    else {
                        instruction.branch_offset = displacement;
                        instruction.branch_target = target.take_value();
                    }
                }
                break;
            case 0xc8: case 0xc9:
                result = fixed(5);
                if (result) {
                    const auto displacement = static_cast<std::int32_t>(be32(code.data() + offset + 1));
                    auto target = branch_target(offset, displacement);
                    if (!target)
                        result = workspace_result_t<void>::failure(std::move(target.error()));
                    else {
                        instruction.branch_offset = displacement;
                        instruction.branch_target = target.take_value();
                    }
                }
                break;
            case 0xb2: case 0xb3: case 0xb4: case 0xb5: case 0xb6: case 0xb7:
            case 0xb8: case 0xbb: case 0xbd: case 0xc0: case 0xc1:
                result = fixed(3);
                if (result)
                    instruction.constant_pool_index = be16(code.data() + offset + 1);
                break;
            case 0xb9: case 0xba:
                result = fixed(5);
                if (result) {
                    instruction.constant_pool_index = be16(code.data() + offset + 1);
                    const auto third = code[static_cast<std::size_t>(offset + 3)];
                    const auto fourth = code[static_cast<std::size_t>(offset + 4)];
                    if ((opcode == 0xb9 && (third == 0 || fourth != 0)) ||
                        (opcode == 0xba && (third != 0 || fourth != 0)))
                        result = workspace_result_t<void>::failure(parse_error(
                            "invoke instruction contains invalid reserved operands", code_offset + offset, 5));
                }
                break;
            case 0xbc:
                result = fixed(2);
                if (result) {
                    instruction.array_type = code[static_cast<std::size_t>(offset + 1)];
                    if (*instruction.array_type < 4 || *instruction.array_type > 11)
                        result = workspace_result_t<void>::failure(parse_error(
                            "newarray operand is invalid", code_offset + offset + 1, 1));
                }
                break;
            case 0xc5:
                result = fixed(4);
                if (result) {
                    instruction.constant_pool_index = be16(code.data() + offset + 1);
                    instruction.dimensions = code[static_cast<std::size_t>(offset + 3)];
                    if (*instruction.dimensions == 0)
                        result = workspace_result_t<void>::failure(parse_error(
                            "multianewarray dimensions is zero", code_offset + offset + 3, 1));
                }
                break;
            case 0xaa: case 0xab: {
                const auto padding = (4u - static_cast<std::uint32_t>((offset + 1u) & 3u)) & 3u;
                const auto header = 1u + padding;
                const auto prefix = opcode == 0xaa ? 12u : 8u;
                if (!require(offset, static_cast<std::uint64_t>(header) + prefix)) {
                    result = workspace_result_t<void>::failure(parse_error(
                        "switch instruction header is truncated", code_offset + offset, header + prefix));
                    break;
                }
                const auto default_displacement = static_cast<std::int32_t>(be32(code.data() + offset + header));
                auto default_target = branch_target(offset, default_displacement);
                if (!default_target) {
                    result = workspace_result_t<void>::failure(std::move(default_target.error()));
                    break;
                }
                std::uint64_t count = 0;
                std::uint64_t table_offset = offset + header + prefix;
                if (opcode == 0xaa) {
                    const auto low = static_cast<std::int32_t>(be32(code.data() + offset + header + 4));
                    const auto high = static_cast<std::int32_t>(be32(code.data() + offset + header + 8));
                    if (high < low) {
                        result = workspace_result_t<void>::failure(parse_error(
                            "tableswitch range is invalid", code_offset + offset, header + prefix));
                        break;
                    }
                    count = static_cast<std::uint64_t>(static_cast<std::int64_t>(high) - low) + 1;
                } else {
                    const auto pairs = static_cast<std::int32_t>(be32(code.data() + offset + header + 4));
                    if (pairs < 0) {
                        result = workspace_result_t<void>::failure(parse_error(
                            "lookupswitch pair count is negative", code_offset + offset, header + prefix));
                        break;
                    }
                    count = static_cast<std::uint32_t>(pairs);
                }
                if (count > limits.max_switch_entries ||
                    count > (code.size() - table_offset) / (opcode == 0xaa ? 4u : 8u)) {
                    result = workspace_result_t<void>::failure(limit_error(
                        "switch table exceeds bounded bytecode limits", count, limits.max_switch_entries));
                    break;
                }
                const auto entry_size = opcode == 0xaa ? 4u : 8u;
                const auto length = static_cast<std::uint64_t>(header) + prefix + count * entry_size;
                result = fixed(length);
                if (!result)
                    break;
                instruction.switch_default_offset = default_displacement;
                instruction.switch_default_target = default_target.take_value();
                std::int32_t prior_key = (std::numeric_limits<std::int32_t>::min)();
                for (std::uint64_t pair = 0; pair < count; ++pair) {
                    const auto entry = table_offset + pair * entry_size;
                    if (opcode == 0xab) {
                        const auto key = static_cast<std::int32_t>(be32(code.data() + entry));
                        if (pair != 0 && key <= prior_key) {
                            result = workspace_result_t<void>::failure(parse_error(
                                "lookupswitch keys are not strictly ordered", code_offset + entry, 4));
                            break;
                        }
                        prior_key = key;
                    }
                    const auto displacement = static_cast<std::int32_t>(be32(code.data() + entry + (opcode == 0xaa ? 0 : 4)));
                    auto target = branch_target(offset, displacement);
                    if (!target) {
                        result = workspace_result_t<void>::failure(std::move(target.error()));
                        break;
                    }
                    instruction.switch_offsets.push_back(displacement);
                    instruction.switch_targets.push_back(target.take_value());
                }
                break;
            }
            case 0xc4: {
                if (!require(offset, 4)) {
                    result = workspace_result_t<void>::failure(parse_error(
                        "wide instruction is truncated", code_offset + offset, 4));
                    break;
                }
                const auto widened = code[static_cast<std::size_t>(offset + 1)];
                const bool local = widened == 0x15 || widened == 0x16 || widened == 0x17 ||
                                   widened == 0x18 || widened == 0x19 || widened == 0x36 ||
                                   widened == 0x37 || widened == 0x38 || widened == 0x39 ||
                                   widened == 0x3a || widened == 0xa9;
                if (!local && widened != 0x84) {
                    result = workspace_result_t<void>::failure(parse_error(
                        "wide prefixes an unsupported opcode", code_offset + offset + 1, 1));
                    break;
                }
                result = fixed(widened == 0x84 ? 6 : 4);
                if (result) {
                    instruction.wide_local_variable_index = be16(code.data() + offset + 2);
                    if (widened == 0x84)
                        instruction.wide_increment = static_cast<std::int16_t>(be16(code.data() + offset + 4));
                }
                break;
            }
            default:
                result = fixed(1);
                break;
        }
        if (!result)
            return workspace_result_t<std::vector<jvm_bytecode_instruction_t>>::failure(std::move(result.error()));
        if (instruction.constant_pool_index) {
            auto checked = validate_constant_operand(pool, *instruction.constant_pool_index,
                                                     opcode, code_offset + offset);
            if (!checked)
                return workspace_result_t<std::vector<jvm_bytecode_instruction_t>>::failure(std::move(checked.error()));
        }
        instructions.push_back(std::move(instruction));
        offset += instructions.back().length;
    }
    const auto boundary = [&](std::uint64_t target) {
        const auto found = std::lower_bound(instructions.begin(), instructions.end(), target,
            [](const jvm_bytecode_instruction_t& instruction, std::uint64_t value) {
                return instruction.offset < value;
            });
        return found != instructions.end() && found->offset == target;
    };
    for (const auto& instruction : instructions) {
        if ((instruction.branch_target && !boundary(*instruction.branch_target)) ||
            (instruction.switch_default_target && !boundary(*instruction.switch_default_target)))
            return workspace_result_t<std::vector<jvm_bytecode_instruction_t>>::failure(parse_error(
                "bytecode branch targets a non-instruction boundary", code_offset + instruction.offset, instruction.length));
        for (const auto target : instruction.switch_targets) {
            if (!boundary(target))
                return workspace_result_t<std::vector<jvm_bytecode_instruction_t>>::failure(parse_error(
                    "switch entry targets a non-instruction boundary", code_offset + instruction.offset, instruction.length));
        }
    }
    return workspace_result_t<std::vector<jvm_bytecode_instruction_t>>::success(std::move(instructions));
}

workspace_result_t<void> parse_debug_attributes(
    const std::vector<jvm_attribute_t>& attributes, const std::vector<cp_entry_t>& pool,
    std::uint32_t code_length, parse_budget_t& budget, const classfile_parse_limits_t& limits,
    jvm_code_attribute_t& code) {
    for (const auto& attribute : attributes) {
        reader_t reader{attribute.raw_data.data(), attribute.raw_data.size(), 0};
        if (attribute.name == "LineNumberTable") {
            auto count = reader.u2();
            if (!count)
                return workspace_result_t<void>::failure(std::move(count.error()));
            if (count.value() > limits.max_line_number_entries ||
                budget.lines > limits.max_line_number_entries - count.value())
                return workspace_result_t<void>::failure(limit_error(
                    "LineNumberTable entry count exceeds limit", count.value(), limits.max_line_number_entries));
            for (std::uint16_t index = 0; index < count.value(); ++index) {
                auto start = reader.u2();
                auto line = reader.u2();
                if (!start)
                    return workspace_result_t<void>::failure(std::move(start.error()));
                if (!line)
                    return workspace_result_t<void>::failure(std::move(line.error()));
                if (start.value() >= code_length)
                    return workspace_result_t<void>::failure(parse_error(
                        "LineNumberTable start_pc exceeds Code attribute", attribute.offset + reader.offset - 4, 2));
                code.line_numbers.push_back({start.value(), line.value()});
            }
            if (reader.offset != reader.size)
                return workspace_result_t<void>::failure(parse_error(
                    "LineNumberTable attribute length is invalid", attribute.offset, attribute.length));
            budget.lines += count.value();
        } else if (attribute.name == "LocalVariableTable") {
            auto count = reader.u2();
            if (!count)
                return workspace_result_t<void>::failure(std::move(count.error()));
            if (count.value() > limits.max_local_variable_entries ||
                budget.locals > limits.max_local_variable_entries - count.value())
                return workspace_result_t<void>::failure(limit_error(
                    "LocalVariableTable entry count exceeds limit", count.value(), limits.max_local_variable_entries));
            for (std::uint16_t index = 0; index < count.value(); ++index) {
                auto start = reader.u2(); auto length = reader.u2(); auto name = reader.u2();
                auto descriptor = reader.u2(); auto slot = reader.u2();
                if (!start) return workspace_result_t<void>::failure(std::move(start.error()));
                if (!length) return workspace_result_t<void>::failure(std::move(length.error()));
                if (!name) return workspace_result_t<void>::failure(std::move(name.error()));
                if (!descriptor) return workspace_result_t<void>::failure(std::move(descriptor.error()));
                if (!slot) return workspace_result_t<void>::failure(std::move(slot.error()));
                const auto* variable_name = cp_utf8(pool, name.value());
                const auto* variable_descriptor = cp_utf8(pool, descriptor.value());
                if (variable_name == nullptr || variable_descriptor == nullptr ||
                    !valid_field_descriptor(*variable_descriptor) ||
                    !add_within(start.value(), length.value(), code_length))
                    return workspace_result_t<void>::failure(parse_error(
                        "LocalVariableTable entry is invalid", attribute.offset + reader.offset - 10, 10));
                jvm_local_variable_t variable;
                variable.start_pc = start.value(); variable.length = length.value();
                variable.name_index = name.value(); variable.descriptor_index = descriptor.value();
                variable.index = slot.value(); variable.name = *variable_name;
                variable.descriptor = *variable_descriptor;
                code.local_variables.push_back(std::move(variable));
            }
            if (reader.offset != reader.size)
                return workspace_result_t<void>::failure(parse_error(
                    "LocalVariableTable attribute length is invalid", attribute.offset, attribute.length));
            budget.locals += count.value();
        }
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<jvm_code_attribute_t> parse_code_attribute(
    const jvm_attribute_t& attribute, const std::vector<cp_entry_t>& pool,
    parse_budget_t& budget, const classfile_parse_limits_t& limits,
    const cancellation_token_t& cancel) {
    reader_t reader{attribute.raw_data.data(), attribute.raw_data.size(), 0};
    auto max_stack = reader.u2(); auto max_locals = reader.u2(); auto code_length = reader.u4();
    if (!max_stack) return workspace_result_t<jvm_code_attribute_t>::failure(std::move(max_stack.error()));
    if (!max_locals) return workspace_result_t<jvm_code_attribute_t>::failure(std::move(max_locals.error()));
    if (!code_length) return workspace_result_t<jvm_code_attribute_t>::failure(std::move(code_length.error()));
    if (code_length.value() == 0 || code_length.value() > limits.max_bytecode_per_method ||
        budget.code_bytes > limits.max_total_code_bytes - code_length.value())
        return workspace_result_t<jvm_code_attribute_t>::failure(limit_error(
            "Code attribute bytecode budget exceeded", code_length.value(), limits.max_total_code_bytes));
    const auto code_file_offset = attribute.offset + 8;
    auto code_bytes = reader.take(code_length.value());
    if (!code_bytes)
        return workspace_result_t<jvm_code_attribute_t>::failure(std::move(code_bytes.error()));
    jvm_code_attribute_t code;
    code.max_stack = max_stack.value(); code.max_locals = max_locals.value();
    code.code_offset = code_file_offset; code.code_length = code_length.value();
    code.code = code_bytes.take_value();
    budget.code_bytes += code.code.size();
    auto exception_count = reader.u2();
    if (!exception_count)
        return workspace_result_t<jvm_code_attribute_t>::failure(std::move(exception_count.error()));
    if (exception_count.value() > limits.max_exception_table_entries)
        return workspace_result_t<jvm_code_attribute_t>::failure(limit_error(
            "Code exception-table count exceeds limit", exception_count.value(), limits.max_exception_table_entries));
    for (std::uint16_t index = 0; index < exception_count.value(); ++index) {
        auto start = reader.u2(); auto end = reader.u2(); auto handler = reader.u2(); auto catch_type = reader.u2();
        if (!start) return workspace_result_t<jvm_code_attribute_t>::failure(std::move(start.error()));
        if (!end) return workspace_result_t<jvm_code_attribute_t>::failure(std::move(end.error()));
        if (!handler) return workspace_result_t<jvm_code_attribute_t>::failure(std::move(handler.error()));
        if (!catch_type) return workspace_result_t<jvm_code_attribute_t>::failure(std::move(catch_type.error()));
        if (start.value() >= end.value() || end.value() > code.code_length || handler.value() >= code.code_length)
            return workspace_result_t<jvm_code_attribute_t>::failure(parse_error(
                "Code exception-table range is invalid", attribute.offset + reader.offset - 8, 8));
        jvm_code_exception_t exception;
        exception.start_pc = start.value(); exception.end_pc = end.value();
        exception.handler_pc = handler.value(); exception.catch_type = catch_type.value();
        if (catch_type.value() != 0) {
            auto entry = cp_required(pool, catch_type.value(), jvm_constant_tag_t::class_ref,
                                     "Code exception-table entry", attribute.offset + reader.offset - 2);
            if (!entry)
                return workspace_result_t<jvm_code_attribute_t>::failure(std::move(entry.error()));
            const auto* name = cp_utf8(pool, entry.value()->first);
            exception.catch_class_name = *name;
        }
        code.exceptions.push_back(std::move(exception));
    }
    auto nested = parse_attributes(reader, pool, budget, limits, cancel);
    if (!nested)
        return workspace_result_t<jvm_code_attribute_t>::failure(std::move(nested.error()));
    if (reader.offset != reader.size)
        return workspace_result_t<jvm_code_attribute_t>::failure(parse_error(
            "Code attribute length is invalid", attribute.offset, attribute.length));
    code.attributes = nested.take_value();
    auto parsed = parse_bytecode(code.code, code.code_offset, pool, limits, cancel);
    if (!parsed)
        return workspace_result_t<jvm_code_attribute_t>::failure(std::move(parsed.error()));
    code.instructions = parsed.take_value();
    auto debug = parse_debug_attributes(code.attributes, pool, code.code_length, budget, limits, code);
    if (!debug)
        return workspace_result_t<jvm_code_attribute_t>::failure(std::move(debug.error()));
    return workspace_result_t<jvm_code_attribute_t>::success(std::move(code));
}

workspace_result_t<void> validate_flags(std::uint16_t flags, std::uint16_t allowed,
                                        std::string_view entity, std::uint64_t offset) {
    if ((flags & ~allowed) != 0)
        return workspace_result_t<void>::failure(parse_error(
            std::string(entity) + " access flags contain reserved bits", offset, 2));
    const auto visibility = flags & (jvm_acc_public | jvm_acc_private | jvm_acc_protected);
    if (visibility != 0 && (visibility & (visibility - 1)) != 0)
        return workspace_result_t<void>::failure(parse_error(
            std::string(entity) + " declares conflicting visibility flags", offset, 2));
    return workspace_result_t<void>::success();
}

workspace_result_t<jvm_field_t> parse_field(reader_t& reader, const std::vector<cp_entry_t>& pool,
                                             parse_budget_t& budget, const classfile_parse_limits_t& limits,
                                             const cancellation_token_t& cancel) {
    const auto offset = reader.offset;
    auto flags = reader.u2(); auto name = reader.u2(); auto descriptor = reader.u2();
    if (!flags) return workspace_result_t<jvm_field_t>::failure(std::move(flags.error()));
    if (!name) return workspace_result_t<jvm_field_t>::failure(std::move(name.error()));
    if (!descriptor) return workspace_result_t<jvm_field_t>::failure(std::move(descriptor.error()));
    auto checked = validate_flags(flags.value(), 0x50dfu, "field", offset);
    if (!checked) return workspace_result_t<jvm_field_t>::failure(std::move(checked.error()));
    if ((flags.value() & jvm_acc_final) != 0 && (flags.value() & jvm_acc_volatile) != 0)
        return workspace_result_t<jvm_field_t>::failure(parse_error("field is both final and volatile", offset, 2));
    const auto* field_name = cp_utf8(pool, name.value());
    const auto* field_descriptor = cp_utf8(pool, descriptor.value());
    if (field_name == nullptr || field_descriptor == nullptr || !valid_unqualified_name(*field_name, false) ||
        !valid_field_descriptor(*field_descriptor))
        return workspace_result_t<jvm_field_t>::failure(parse_error("field name or descriptor is invalid", offset, 6));
    auto attributes = parse_attributes(reader, pool, budget, limits, cancel);
    if (!attributes) return workspace_result_t<jvm_field_t>::failure(std::move(attributes.error()));
    jvm_field_t field;
    field.access_flags = flags.value(); field.name_index = name.value(); field.descriptor_index = descriptor.value();
    field.name = *field_name; field.descriptor = *field_descriptor; field.attributes = attributes.take_value();
    field.is_public = (field.access_flags & jvm_acc_public) != 0; field.is_private = (field.access_flags & jvm_acc_private) != 0;
    field.is_protected = (field.access_flags & jvm_acc_protected) != 0; field.is_static = (field.access_flags & jvm_acc_static) != 0;
    field.is_final = (field.access_flags & jvm_acc_final) != 0; field.is_volatile = (field.access_flags & jvm_acc_volatile) != 0;
    field.is_transient = (field.access_flags & jvm_acc_transient) != 0; field.is_synthetic = (field.access_flags & jvm_acc_synthetic) != 0;
    field.is_enum = (field.access_flags & jvm_acc_enum) != 0;
    return workspace_result_t<jvm_field_t>::success(std::move(field));
}

workspace_result_t<std::vector<std::string>> parse_exceptions_attribute(
    const jvm_attribute_t& attribute, const std::vector<cp_entry_t>& pool) {
    reader_t reader{attribute.raw_data.data(), attribute.raw_data.size(), 0};
    auto count = reader.u2();
    if (!count)
        return workspace_result_t<std::vector<std::string>>::failure(std::move(count.error()));
    std::vector<std::string> exceptions;
    exceptions.reserve(count.value());
    for (std::uint16_t index = 0; index < count.value(); ++index) {
        auto exception = reader.u2();
        if (!exception)
            return workspace_result_t<std::vector<std::string>>::failure(std::move(exception.error()));
        auto entry = cp_required(pool, exception.value(), jvm_constant_tag_t::class_ref,
                                 "Exceptions attribute", attribute.offset + reader.offset - 2);
        if (!entry)
            return workspace_result_t<std::vector<std::string>>::failure(std::move(entry.error()));
        exceptions.push_back(*cp_utf8(pool, entry.value()->first));
    }
    if (reader.offset != reader.size)
        return workspace_result_t<std::vector<std::string>>::failure(parse_error(
            "Exceptions attribute length is invalid", attribute.offset, attribute.length));
    return workspace_result_t<std::vector<std::string>>::success(std::move(exceptions));
}

workspace_result_t<jvm_method_t> parse_method(reader_t& reader, const std::vector<cp_entry_t>& pool,
                                               parse_budget_t& budget, const classfile_parse_limits_t& limits,
                                               const cancellation_token_t& cancel) {
    const auto offset = reader.offset;
    auto flags = reader.u2(); auto name = reader.u2(); auto descriptor = reader.u2();
    if (!flags) return workspace_result_t<jvm_method_t>::failure(std::move(flags.error()));
    if (!name) return workspace_result_t<jvm_method_t>::failure(std::move(name.error()));
    if (!descriptor) return workspace_result_t<jvm_method_t>::failure(std::move(descriptor.error()));
    auto checked = validate_flags(flags.value(), 0x1dffu, "method", offset);
    if (!checked) return workspace_result_t<jvm_method_t>::failure(std::move(checked.error()));
    const auto* method_name = cp_utf8(pool, name.value());
    const auto* method_descriptor = cp_utf8(pool, descriptor.value());
    if (method_name == nullptr || method_descriptor == nullptr || !valid_unqualified_name(*method_name, true) ||
        !valid_method_descriptor(*method_descriptor))
        return workspace_result_t<jvm_method_t>::failure(parse_error("method name or descriptor is invalid", offset, 6));
    const bool abstract = (flags.value() & jvm_acc_abstract) != 0;
    if (abstract && (flags.value() & (jvm_acc_private | jvm_acc_static | jvm_acc_final | jvm_acc_synchronized | jvm_acc_native)) != 0)
        return workspace_result_t<jvm_method_t>::failure(parse_error("abstract method has incompatible flags", offset, 2));
    auto attributes = parse_attributes(reader, pool, budget, limits, cancel);
    if (!attributes) return workspace_result_t<jvm_method_t>::failure(std::move(attributes.error()));
    jvm_method_t method;
    method.access_flags = flags.value(); method.name_index = name.value(); method.descriptor_index = descriptor.value();
    method.name = *method_name; method.descriptor = *method_descriptor; method.attributes = attributes.take_value();
    std::uint32_t code_count = 0;
    for (const auto& attribute : method.attributes) {
        if (attribute.name == "Code") {
            if (++code_count != 1)
                return workspace_result_t<jvm_method_t>::failure(parse_error("method has duplicate Code attributes", attribute.offset, attribute.length));
            auto code = parse_code_attribute(attribute, pool, budget, limits, cancel);
            if (!code) return workspace_result_t<jvm_method_t>::failure(std::move(code.error()));
            method.code = code.take_value();
        } else if (attribute.name == "Exceptions") {
            auto exceptions = parse_exceptions_attribute(attribute, pool);
            if (!exceptions) return workspace_result_t<jvm_method_t>::failure(std::move(exceptions.error()));
            method.declared_exceptions = exceptions.take_value();
        }
    }
    const bool native = (method.access_flags & jvm_acc_native) != 0;
    if ((abstract || native) != !method.code.has_value())
        return workspace_result_t<jvm_method_t>::failure(parse_error(
            "method Code attribute conflicts with method flags", offset, 2));
    method.is_public = (method.access_flags & jvm_acc_public) != 0; method.is_private = (method.access_flags & jvm_acc_private) != 0;
    method.is_protected = (method.access_flags & jvm_acc_protected) != 0; method.is_static = (method.access_flags & jvm_acc_static) != 0;
    method.is_final = (method.access_flags & jvm_acc_final) != 0; method.is_synchronized = (method.access_flags & jvm_acc_synchronized) != 0;
    method.is_bridge = (method.access_flags & jvm_acc_bridge) != 0; method.is_varargs = (method.access_flags & jvm_acc_varargs) != 0;
    method.is_native = native; method.is_abstract = abstract; method.is_strict = (method.access_flags & jvm_acc_strict) != 0;
    method.is_synthetic = (method.access_flags & jvm_acc_synthetic) != 0;
    return workspace_result_t<jvm_method_t>::success(std::move(method));
}

workspace_result_t<void> parse_class_attributes(classfile_image_t& image,
                                                 const std::vector<cp_entry_t>& pool,
                                                 const classfile_parse_limits_t& limits) {
    bool source_seen = false; bool signature_seen = false; bool bootstrap_seen = false;
    for (const auto& attribute : image.attributes) {
        reader_t reader{attribute.raw_data.data(), attribute.raw_data.size(), 0};
        if (attribute.name == "SourceFile") {
            if (source_seen) return workspace_result_t<void>::failure(parse_error("duplicate SourceFile attribute", attribute.offset, attribute.length));
            source_seen = true;
            auto index = reader.u2();
            const auto* value = index ? cp_utf8(pool, index.value()) : nullptr;
            if (!index || value == nullptr || reader.offset != reader.size)
                return workspace_result_t<void>::failure(parse_error("SourceFile attribute is invalid", attribute.offset, attribute.length));
            image.source_file = *value;
        } else if (attribute.name == "Signature") {
            if (signature_seen) return workspace_result_t<void>::failure(parse_error("duplicate Signature attribute", attribute.offset, attribute.length));
            signature_seen = true;
            auto index = reader.u2();
            const auto* value = index ? cp_utf8(pool, index.value()) : nullptr;
            if (!index || value == nullptr || reader.offset != reader.size)
                return workspace_result_t<void>::failure(parse_error("Signature attribute is invalid", attribute.offset, attribute.length));
            image.signature = *value;
        } else if (attribute.name == "InnerClasses") {
            auto count = reader.u2();
            if (!count) return workspace_result_t<void>::failure(std::move(count.error()));
            if (count.value() > limits.max_inner_classes)
                return workspace_result_t<void>::failure(limit_error("InnerClasses count exceeds limit", count.value(), limits.max_inner_classes));
            for (std::uint16_t index = 0; index < count.value(); ++index) {
                auto inner = reader.u2(); auto outer = reader.u2(); auto name = reader.u2(); auto flags = reader.u2();
                if (!inner) return workspace_result_t<void>::failure(std::move(inner.error()));
                if (!outer) return workspace_result_t<void>::failure(std::move(outer.error()));
                if (!name) return workspace_result_t<void>::failure(std::move(name.error()));
                if (!flags) return workspace_result_t<void>::failure(std::move(flags.error()));
                auto inner_entry = cp_required(pool, inner.value(), jvm_constant_tag_t::class_ref, "InnerClasses attribute", attribute.offset + reader.offset - 8);
                if (!inner_entry) return workspace_result_t<void>::failure(std::move(inner_entry.error()));
                jvm_inner_class_t item;
                item.inner_class_info_index = inner.value(); item.outer_class_info_index = outer.value(); item.inner_name_index = name.value(); item.access_flags = flags.value();
                item.inner_class_name = *cp_utf8(pool, inner_entry.value()->first);
                if (outer.value() != 0) {
                    auto outer_entry = cp_required(pool, outer.value(), jvm_constant_tag_t::class_ref, "InnerClasses attribute", attribute.offset + reader.offset - 6);
                    if (!outer_entry) return workspace_result_t<void>::failure(std::move(outer_entry.error()));
                    item.outer_class_name = *cp_utf8(pool, outer_entry.value()->first);
                }
                if (name.value() != 0) {
                    const auto* inner_name = cp_utf8(pool, name.value());
                    if (inner_name == nullptr || !valid_unqualified_name(*inner_name, false))
                        return workspace_result_t<void>::failure(parse_error("InnerClasses name is invalid", attribute.offset + reader.offset - 4, 2));
                    item.inner_name = *inner_name;
                }
                image.inner_classes.push_back(std::move(item));
            }
            if (reader.offset != reader.size) return workspace_result_t<void>::failure(parse_error("InnerClasses attribute length is invalid", attribute.offset, attribute.length));
        } else if (attribute.name == "BootstrapMethods") {
            if (bootstrap_seen) return workspace_result_t<void>::failure(parse_error("duplicate BootstrapMethods attribute", attribute.offset, attribute.length));
            bootstrap_seen = true;
            auto count = reader.u2();
            if (!count) return workspace_result_t<void>::failure(std::move(count.error()));
            if (count.value() > limits.max_bootstrap_methods)
                return workspace_result_t<void>::failure(limit_error("BootstrapMethods count exceeds limit", count.value(), limits.max_bootstrap_methods));
            for (std::uint16_t index = 0; index < count.value(); ++index) {
                auto handle = reader.u2(); auto arguments = reader.u2();
                if (!handle) return workspace_result_t<void>::failure(std::move(handle.error()));
                if (!arguments) return workspace_result_t<void>::failure(std::move(arguments.error()));
                if (arguments.value() > limits.max_bootstrap_arguments)
                    return workspace_result_t<void>::failure(limit_error("bootstrap argument count exceeds limit", arguments.value(), limits.max_bootstrap_arguments));
                auto handle_entry = cp_required(pool, handle.value(), jvm_constant_tag_t::method_handle, "BootstrapMethods attribute", attribute.offset + reader.offset - 4);
                if (!handle_entry) return workspace_result_t<void>::failure(std::move(handle_entry.error()));
                jvm_bootstrap_method_t item; item.bootstrap_method_ref = handle.value(); item.bootstrap_arguments.reserve(arguments.value());
                for (std::uint16_t argument = 0; argument < arguments.value(); ++argument) {
                    auto value = reader.u2();
                    if (!value) return workspace_result_t<void>::failure(std::move(value.error()));
                    if (cp_at(pool, value.value()) == nullptr)
                        return workspace_result_t<void>::failure(parse_error("bootstrap argument references invalid constant-pool entry", attribute.offset + reader.offset - 2, 2));
                    item.bootstrap_arguments.push_back(value.value());
                }
                image.bootstrap_methods.push_back(std::move(item));
            }
            if (reader.offset != reader.size) return workspace_result_t<void>::failure(parse_error("BootstrapMethods attribute length is invalid", attribute.offset, attribute.length));
        }
    }
    for (std::size_t index = 1; index < pool.size(); ++index) {
        const auto& entry = pool[index];
        if (!entry.valid || (entry.tag != jvm_constant_tag_t::dynamic && entry.tag != jvm_constant_tag_t::invoke_dynamic))
            continue;
        if (entry.bootstrap_index >= image.bootstrap_methods.size())
            return workspace_result_t<void>::failure(parse_error("dynamic constant references missing bootstrap method", entry.file_offset, 4));
    }
    return workspace_result_t<void>::success();
}

jvm_constant_pool_entry_t public_entry(const cp_entry_t& entry, std::uint16_t index) {
    jvm_constant_pool_entry_t value;
    value.tag = entry.tag; value.index = index; value.file_offset = entry.file_offset; value.utf8_value = entry.utf8;
    value.int_float_value = entry.scalar; value.long_double_value = entry.wide_scalar; value.ref_index1 = entry.first; value.ref_index2 = entry.second;
    value.reference_kind = entry.reference_kind; value.bootstrap_method_attr_index = entry.bootstrap_index;
    value.is_double_slot = entry.double_slot; value.valid = entry.valid;
    return value;
}

} 

const char* jvm_constant_tag_name(jvm_constant_tag_t tag) noexcept {
    switch (tag) {
        case jvm_constant_tag_t::utf8: return "Utf8"; case jvm_constant_tag_t::integer: return "Integer";
        case jvm_constant_tag_t::float_: return "Float"; case jvm_constant_tag_t::long_: return "Long";
        case jvm_constant_tag_t::double_: return "Double"; case jvm_constant_tag_t::class_ref: return "Class";
        case jvm_constant_tag_t::string_ref: return "String"; case jvm_constant_tag_t::fieldref: return "Fieldref";
        case jvm_constant_tag_t::methodref: return "Methodref"; case jvm_constant_tag_t::interface_methodref: return "InterfaceMethodref";
        case jvm_constant_tag_t::name_and_type: return "NameAndType"; case jvm_constant_tag_t::method_handle: return "MethodHandle";
        case jvm_constant_tag_t::method_type: return "MethodType"; case jvm_constant_tag_t::dynamic: return "Dynamic";
        case jvm_constant_tag_t::invoke_dynamic: return "InvokeDynamic"; case jvm_constant_tag_t::module_ref: return "Module";
        case jvm_constant_tag_t::package_ref: return "Package"; default: return "Invalid";
    }
}

const char* jvm_major_version_name(std::uint16_t major) noexcept {
    switch (major) {
        case 45: return "JDK1.0/1.1"; case 46: return "JDK1.2"; case 47: return "JDK1.3"; case 48: return "JDK1.4";
        case 49: return "J2SE5"; case 50: return "J2SE6"; case 51: return "J7"; case 52: return "J8"; case 53: return "J9";
        case 54: return "J10"; case 55: return "J11"; case 56: return "J12"; case 57: return "J13"; case 58: return "J14";
        case 59: return "J15"; case 60: return "J16"; case 61: return "J17"; case 62: return "J18"; case 63: return "J19";
        case 64: return "J20"; case 65: return "J21"; case 66: return "J22"; case 67: return "J23"; case 68: return "J24";
        case 69: return "J25"; case 70: return "J26"; default: return "unknown";
    }
}

const char* jvm_opcode_mnemonic(std::uint8_t opcode) noexcept {
    return opcode < opcode_names.size() ? opcode_names[opcode] : "reserved";
}

workspace_result_t<classfile_image_t> parse_classfile_image(
    const byte_provider_t& provider, const classfile_parse_limits_t& limits,
    const cancellation_token_t& cancel) {
    if (stopped(cancel)) return workspace_result_t<classfile_image_t>::failure(stop_error(cancel));
    if (limits.max_classfile_bytes < 10 || limits.max_attribute_size == 0 || limits.max_bytecode_per_method == 0 ||
        limits.max_total_attribute_bytes < limits.max_attribute_size || limits.max_total_code_bytes < limits.max_bytecode_per_method)
        return workspace_result_t<classfile_image_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument, "classfile parse limits are internally inconsistent", "classfile_parse"));
    const auto file_size = provider.size();
    if (file_size < 10) return workspace_result_t<classfile_image_t>::failure(parse_error("classfile is shorter than its fixed header", 0, file_size));
    if (file_size > limits.max_classfile_bytes) return workspace_result_t<classfile_image_t>::failure(limit_error("classfile size exceeds limit", file_size, limits.max_classfile_bytes));
    auto input = provider.read_vector(0, file_size, limits.max_classfile_bytes, cancel);
    if (!input) return workspace_result_t<classfile_image_t>::failure(std::move(input.error()));
    const auto bytes = input.take_value();
    reader_t reader{bytes.data(), bytes.size(), 0};
    auto magic = reader.u4(); auto minor = reader.u2(); auto major = reader.u2(); auto count = reader.u2();
    if (!magic) return workspace_result_t<classfile_image_t>::failure(std::move(magic.error()));
    if (!minor) return workspace_result_t<classfile_image_t>::failure(std::move(minor.error()));
    if (!major) return workspace_result_t<classfile_image_t>::failure(std::move(major.error()));
    if (!count) return workspace_result_t<classfile_image_t>::failure(std::move(count.error()));
    if (magic.value() != classfile_magic) return workspace_result_t<classfile_image_t>::failure(parse_error("classfile magic is invalid", 0, 4));
    if (major.value() < 45 || major.value() > 70) return workspace_result_t<classfile_image_t>::failure(parse_error("classfile major version is unsupported", 6, 2));
    auto pool = parse_constant_pool(reader, count.value(), major.value(), limits, cancel);
    if (!pool) return workspace_result_t<classfile_image_t>::failure(std::move(pool.error()));
    auto cp = pool.take_value();
    auto validated_pool = validate_constant_pool(cp, major.value());
    if (!validated_pool) return workspace_result_t<classfile_image_t>::failure(std::move(validated_pool.error()));
    const auto class_offset = reader.offset;
    auto flags = reader.u2(); auto this_class = reader.u2(); auto super_class = reader.u2();
    if (!flags) return workspace_result_t<classfile_image_t>::failure(std::move(flags.error()));
    if (!this_class) return workspace_result_t<classfile_image_t>::failure(std::move(this_class.error()));
    if (!super_class) return workspace_result_t<classfile_image_t>::failure(std::move(super_class.error()));
    auto flags_valid = validate_flags(flags.value(), 0xf631u, "class", class_offset);
    if (!flags_valid) return workspace_result_t<classfile_image_t>::failure(std::move(flags_valid.error()));
    const bool module = (flags.value() & jvm_acc_module) != 0;
    const bool interface = (flags.value() & jvm_acc_interface) != 0;
    if ((interface && ((flags.value() & jvm_acc_abstract) == 0 || (flags.value() & jvm_acc_final) != 0)) ||
        ((flags.value() & jvm_acc_annotation) != 0 && !interface) || (module && major.value() < 53))
        return workspace_result_t<classfile_image_t>::failure(parse_error("class access flags are inconsistent", class_offset, 2));
    auto class_entry = cp_required(cp, this_class.value(), jvm_constant_tag_t::class_ref, "this_class", class_offset + 2);
    if (!class_entry) return workspace_result_t<classfile_image_t>::failure(std::move(class_entry.error()));
    const auto* this_name = cp_utf8(cp, class_entry.value()->first);
    if (this_name == nullptr || this_name->empty()) return workspace_result_t<classfile_image_t>::failure(parse_error("this_class name is invalid", class_offset + 2, 2));
    std::string super_name;
    if (super_class.value() != 0) {
        auto super_entry = cp_required(cp, super_class.value(), jvm_constant_tag_t::class_ref, "super_class", class_offset + 4);
        if (!super_entry) return workspace_result_t<classfile_image_t>::failure(std::move(super_entry.error()));
        super_name = *cp_utf8(cp, super_entry.value()->first);
    } else if (!module && *this_name != "java/lang/Object") {
        return workspace_result_t<classfile_image_t>::failure(parse_error("super_class is zero for a non-root class", class_offset + 4, 2));
    }
    auto interface_count = reader.u2();
    if (!interface_count) return workspace_result_t<classfile_image_t>::failure(std::move(interface_count.error()));
    if (interface_count.value() > limits.max_interfaces) return workspace_result_t<classfile_image_t>::failure(limit_error("interface count exceeds limit", interface_count.value(), limits.max_interfaces));
    std::vector<std::uint16_t> interfaces; std::vector<std::string> interface_names;
    interfaces.reserve(interface_count.value()); interface_names.reserve(interface_count.value());
    for (std::uint16_t index = 0; index < interface_count.value(); ++index) {
        auto value = reader.u2(); if (!value) return workspace_result_t<classfile_image_t>::failure(std::move(value.error()));
        auto entry = cp_required(cp, value.value(), jvm_constant_tag_t::class_ref, "interface", reader.offset - 2);
        if (!entry) return workspace_result_t<classfile_image_t>::failure(std::move(entry.error()));
        interfaces.push_back(value.value()); interface_names.push_back(*cp_utf8(cp, entry.value()->first));
    }
    parse_budget_t budget;
    auto field_count = reader.u2(); if (!field_count) return workspace_result_t<classfile_image_t>::failure(std::move(field_count.error()));
    if (field_count.value() > limits.max_fields) return workspace_result_t<classfile_image_t>::failure(limit_error("field count exceeds limit", field_count.value(), limits.max_fields));
    std::vector<jvm_field_t> fields; fields.reserve(field_count.value());
    for (std::uint16_t index = 0; index < field_count.value(); ++index) {
        if (stopped(cancel)) return workspace_result_t<classfile_image_t>::failure(stop_error(cancel));
        auto field = parse_field(reader, cp, budget, limits, cancel); if (!field) return workspace_result_t<classfile_image_t>::failure(std::move(field.error()));
        fields.push_back(field.take_value());
    }
    auto method_count = reader.u2(); if (!method_count) return workspace_result_t<classfile_image_t>::failure(std::move(method_count.error()));
    if (method_count.value() > limits.max_methods) return workspace_result_t<classfile_image_t>::failure(limit_error("method count exceeds limit", method_count.value(), limits.max_methods));
    std::vector<jvm_method_t> methods; methods.reserve(method_count.value());
    for (std::uint16_t index = 0; index < method_count.value(); ++index) {
        if (stopped(cancel)) return workspace_result_t<classfile_image_t>::failure(stop_error(cancel));
        auto method = parse_method(reader, cp, budget, limits, cancel); if (!method) return workspace_result_t<classfile_image_t>::failure(std::move(method.error()));
        methods.push_back(method.take_value());
    }
    auto attributes = parse_attributes(reader, cp, budget, limits, cancel);
    if (!attributes) return workspace_result_t<classfile_image_t>::failure(std::move(attributes.error()));
    if (reader.offset != reader.size) return workspace_result_t<classfile_image_t>::failure(parse_error("trailing classfile bytes are not permitted", reader.offset, reader.size - reader.offset));
    classfile_image_t image;
    image.magic = magic.value(); image.minor_version = minor.value(); image.major_version = major.value(); image.access_flags = flags.value();
    image.this_class = this_class.value(); image.super_class = super_class.value(); image.this_class_name = *this_name; image.super_class_name = std::move(super_name);
    image.interfaces = std::move(interfaces); image.interface_names = std::move(interface_names); image.fields = std::move(fields); image.methods = std::move(methods); image.attributes = attributes.take_value();
    image.constant_pool.reserve(cp.size());
    for (std::uint16_t index = 0; index < cp.size(); ++index) image.constant_pool.push_back(public_entry(cp[index], index));
    image.is_public = (flags.value() & jvm_acc_public) != 0; image.is_final = (flags.value() & jvm_acc_final) != 0; image.is_super = (flags.value() & jvm_acc_super) != 0;
    image.is_interface = interface; image.is_abstract = (flags.value() & jvm_acc_abstract) != 0; image.is_synthetic = (flags.value() & jvm_acc_synthetic) != 0;
    image.is_annotation = (flags.value() & jvm_acc_annotation) != 0; image.is_enum = (flags.value() & jvm_acc_enum) != 0; image.is_module = module;
    auto class_attributes = parse_class_attributes(image, cp, limits); if (!class_attributes) return workspace_result_t<classfile_image_t>::failure(std::move(class_attributes.error()));
    for (const auto& method : image.methods) {
        if (!method.code) continue;
        image.line_number_table.insert(image.line_number_table.end(), method.code->line_numbers.begin(), method.code->line_numbers.end());
        image.local_variable_table.insert(image.local_variable_table.end(), method.code->local_variables.begin(), method.code->local_variables.end());
        for (const auto& instruction : method.code->instructions) {
            if (instruction.opcode != 0xba || !instruction.constant_pool_index) continue;
            const auto* dynamic = cp_at(cp, *instruction.constant_pool_index);
            const auto* name_type = cp_at(cp, dynamic->first);
            jvm_invokedynamic_reference_t reference;
            reference.code_offset = method.code->code_offset + instruction.offset;
            reference.constant_pool_index = *instruction.constant_pool_index; reference.bootstrap_method_index = dynamic->bootstrap_index;
            reference.name = *cp_utf8(cp, name_type->first); reference.descriptor = *cp_utf8(cp, name_type->second);
            image.invokedynamic_references.push_back(std::move(reference));
        }
    }
    image.normalized.format = format_id_t::classfile; image.normalized.architecture = architecture_id_t::jvm_bytecode;
    image.normalized.architecture_mode = architecture_mode_t::jvm; image.normalized.abi = abi_id_t::jvm; image.normalized.endian = endian_t::big;
    image.normalized.address_width_bits = 32; image.normalized.image_base = 0; image.normalized.image_size = file_size; image.normalized.header_size = 10;
    image.normalized.format_name = "JVM classfile"; image.normalized.member = provider.member_metadata();
    image.normalized.provider_source = provider.identity().normalized_source; image.normalized.provider_size = file_size;
    return workspace_result_t<classfile_image_t>::success(std::move(image));
}

workspace_result_t<classfile_image_t> parse_classfile_image(const byte_provider_t& provider,
                                                             const cancellation_token_t& cancel) {
    return parse_classfile_image(provider, classfile_parse_limits_t{}, cancel);
}

workspace_result_t<std::shared_ptr<const workspace_image_t>> parse_classfile(
    const byte_provider_t& provider, const classfile_parse_limits_t& limits,
    const cancellation_token_t& cancel) {
    auto image = parse_classfile_image(provider, limits, cancel);
    if (!image) return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(std::move(image.error()));
    return workspace_result_t<std::shared_ptr<const workspace_image_t>>::success(
        std::make_shared<const workspace_image_t>(std::move(image.value().normalized)));
}

workspace_result_t<std::shared_ptr<const workspace_image_t>> parse_classfile(
    const byte_provider_t& provider, const cancellation_token_t& cancel) {
    return parse_classfile(provider, classfile_parse_limits_t{}, cancel);
}

}
