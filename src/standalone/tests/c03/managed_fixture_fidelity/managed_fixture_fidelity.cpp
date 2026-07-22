#include "managed_fixture_fidelity.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <limits>
#include <set>
#include <utility>

namespace aida::analysis::c03
{
namespace
{
    constexpr std::uint32_t dex_header_size = 112U;

    std::uint16_t le16(const std::vector<std::uint8_t>& bytes, std::size_t offset)
    {
        return static_cast<std::uint16_t>(bytes[offset]) |
            static_cast<std::uint16_t>(bytes[offset + 1U] << 8U);
    }

    std::uint32_t le32(const std::vector<std::uint8_t>& bytes, std::size_t offset)
    {
        return static_cast<std::uint32_t>(bytes[offset]) |
            (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
            (static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U) |
            (static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U);
    }

    void put_le32(std::vector<std::uint8_t>& bytes, std::size_t offset,
        std::uint32_t value)
    {
        bytes[offset] = static_cast<std::uint8_t>(value);
        bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
        bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 16U);
        bytes[offset + 3U] = static_cast<std::uint8_t>(value >> 24U);
    }

    std::uint32_t rotate_left(std::uint32_t value, unsigned shift) noexcept
    {
        return (value << shift) | (value >> (32U - shift));
    }

    std::uint32_t crc32(const std::uint8_t* bytes, std::size_t size) noexcept
    {
        std::uint32_t value = 0xffffffffU;
        for (std::size_t index = 0; index < size; ++index) {
            value ^= bytes[index];
            for (unsigned bit = 0U; bit < 8U; ++bit)
                value = (value >> 1U) ^
                    (0xedb88320U & (0U - (value & 1U)));
        }
        return ~value;
    }

    bool span_within(std::uint64_t offset, std::uint64_t size,
        std::uint64_t limit) noexcept
    {
        return offset <= limit && size <= limit - offset;
    }

    managed_fixture_fidelity_result_t failure(std::string error)
    {
        managed_fixture_fidelity_result_t result;
        result.error = std::move(error);
        return result;
    }

    std::uint64_t fixed_map_width(std::uint16_t type) noexcept
    {
        switch (type) {
        case 0x0000U: return 112U;
        case 0x0001U: return 4U;
        case 0x0002U: return 4U;
        case 0x0003U: return 12U;
        case 0x0004U: return 8U;
        case 0x0005U: return 8U;
        case 0x0006U: return 32U;
        default: return 0U;
        }
    }
}

std::array<std::uint8_t, 20> c03_dex_sha1(
    const std::vector<std::uint8_t>& bytes, std::size_t offset)
{
    std::array<std::uint8_t, 20> digest{};
    if (offset > bytes.size())
        return digest;
    std::vector<std::uint8_t> message(bytes.begin() +
        static_cast<std::ptrdiff_t>(offset), bytes.end());
    const auto original_size = message.size();
    if (original_size > (std::numeric_limits<std::uint64_t>::max)() / 8U)
        return digest;
    const auto bit_length = static_cast<std::uint64_t>(original_size) * 8U;
    message.push_back(0x80U);
    while ((message.size() & 63U) != 56U)
        message.push_back(0U);
    for (int shift = 56; shift >= 0; shift -= 8)
        message.push_back(static_cast<std::uint8_t>(bit_length >> shift));
    std::uint32_t h0 = 0x67452301U;
    std::uint32_t h1 = 0xefcdab89U;
    std::uint32_t h2 = 0x98badcfeU;
    std::uint32_t h3 = 0x10325476U;
    std::uint32_t h4 = 0xc3d2e1f0U;
    std::array<std::uint32_t, 80> words{};
    for (std::size_t block = 0; block < message.size(); block += 64U) {
        for (std::size_t index = 0; index < 16U; ++index) {
            const auto base = block + index * 4U;
            words[index] = (static_cast<std::uint32_t>(message[base]) << 24U) |
                (static_cast<std::uint32_t>(message[base + 1U]) << 16U) |
                (static_cast<std::uint32_t>(message[base + 2U]) << 8U) |
                static_cast<std::uint32_t>(message[base + 3U]);
        }
        for (std::size_t index = 16U; index < words.size(); ++index)
            words[index] = rotate_left(words[index - 3U] ^ words[index - 8U] ^
                words[index - 14U] ^ words[index - 16U], 1U);
        std::uint32_t a = h0;
        std::uint32_t b = h1;
        std::uint32_t c = h2;
        std::uint32_t d = h3;
        std::uint32_t e = h4;
        for (std::size_t index = 0; index < words.size(); ++index) {
            std::uint32_t function = 0;
            std::uint32_t constant = 0;
            if (index < 20U) {
                function = (b & c) | ((~b) & d);
                constant = 0x5a827999U;
            } else if (index < 40U) {
                function = b ^ c ^ d;
                constant = 0x6ed9eba1U;
            } else if (index < 60U) {
                function = (b & c) | (b & d) | (c & d);
                constant = 0x8f1bbcdcU;
            } else {
                function = b ^ c ^ d;
                constant = 0xca62c1d6U;
            }
            const auto temporary = rotate_left(a, 5U) + function + e +
                constant + words[index];
            e = d;
            d = c;
            c = rotate_left(b, 30U);
            b = a;
            a = temporary;
        }
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }
    const std::array<std::uint32_t, 5> state{h0, h1, h2, h3, h4};
    for (std::size_t index = 0; index < state.size(); ++index) {
        digest[index * 4U] = static_cast<std::uint8_t>(state[index] >> 24U);
        digest[index * 4U + 1U] = static_cast<std::uint8_t>(state[index] >> 16U);
        digest[index * 4U + 2U] = static_cast<std::uint8_t>(state[index] >> 8U);
        digest[index * 4U + 3U] = static_cast<std::uint8_t>(state[index]);
    }
    return digest;
}

std::uint32_t c03_dex_adler32(const std::vector<std::uint8_t>& bytes,
    std::size_t offset) noexcept
{
    if (offset > bytes.size())
        return 0U;
    constexpr std::uint32_t modulus = 65521U;
    std::uint32_t first = 1U;
    std::uint32_t second = 0U;
    for (std::size_t cursor = offset; cursor < bytes.size();) {
        const auto end = (std::min)(bytes.size(), cursor + 5552U);
        while (cursor < end) {
            first += bytes[cursor++];
            second += first;
        }
        first %= modulus;
        second %= modulus;
    }
    return (second << 16U) | first;
}

bool seal_c03_dex(std::vector<std::uint8_t>& bytes, std::string& error)
{
    if (bytes.size() < dex_header_size || bytes.size() >
        (std::numeric_limits<std::uint32_t>::max)()) {
        error = "DEX integrity input size is invalid";
        return false;
    }
    const auto signature = c03_dex_sha1(bytes, 32U);
    std::copy(signature.begin(), signature.end(), bytes.begin() + 12);
    put_le32(bytes, 8U, c03_dex_adler32(bytes, 12U));
    error.clear();
    return true;
}

managed_fixture_fidelity_result_t validate_c03_dex_fidelity(
    const std::vector<std::uint8_t>& bytes)
{
    if (bytes.size() < dex_header_size)
        return failure("DEX fixture is truncated before its header");
    const std::array<std::uint8_t, 8> expected_magic{
        'd', 'e', 'x', '\n', '0', '3', '5', 0};
    if (!std::equal(expected_magic.begin(), expected_magic.end(), bytes.begin()))
        return failure("DEX fixture magic or version is invalid");
    managed_fixture_fidelity_result_t result;
    auto& layout = result.dex;
    layout.file_size = le32(bytes, 32U);
    const auto header_size = le32(bytes, 36U);
    const auto endian_tag = le32(bytes, 40U);
    layout.map_offset = le32(bytes, 52U);
    layout.string_count = le32(bytes, 56U);
    const auto string_offset = le32(bytes, 60U);
    layout.type_count = le32(bytes, 64U);
    const auto type_offset = le32(bytes, 68U);
    layout.proto_count = le32(bytes, 72U);
    const auto proto_offset = le32(bytes, 76U);
    const auto field_count = le32(bytes, 80U);
    const auto field_offset = le32(bytes, 84U);
    layout.method_count = le32(bytes, 88U);
    const auto method_offset = le32(bytes, 92U);
    layout.class_count = le32(bytes, 96U);
    const auto class_offset = le32(bytes, 100U);
    const auto data_size = le32(bytes, 104U);
    layout.data_offset = le32(bytes, 108U);
    if (layout.file_size != bytes.size() || header_size != dex_header_size ||
        endian_tag != 0x12345678U || layout.map_offset == 0U ||
        (layout.map_offset & 3U) != 0U || layout.data_offset == 0U ||
        (layout.data_offset & 3U) != 0U ||
        !span_within(layout.data_offset, data_size, bytes.size()) ||
        static_cast<std::uint64_t>(layout.data_offset) + data_size != bytes.size())
        return failure("DEX fixture header ranges are inconsistent");
    const auto table_valid = [&](std::uint32_t count, std::uint32_t offset,
        std::uint32_t width) {
        return count == 0U ? offset == 0U :
            (offset >= dex_header_size && (offset & 3U) == 0U &&
             span_within(offset, static_cast<std::uint64_t>(count) * width,
                 layout.data_offset));
    };
    if (!table_valid(layout.string_count, string_offset, 4U) ||
        !table_valid(layout.type_count, type_offset, 4U) ||
        !table_valid(layout.proto_count, proto_offset, 12U) ||
        !table_valid(field_count, field_offset, 8U) ||
        !table_valid(layout.method_count, method_offset, 8U) ||
        !table_valid(layout.class_count, class_offset, 32U))
        return failure("DEX fixture identifier table range is invalid");
    if (layout.string_count != 14U || layout.type_count != 5U ||
        layout.proto_count != 2U || field_count != 0U ||
        layout.method_count != 5U || layout.class_count != 1U)
        return failure("DEX fixture semantic table cardinality is invalid");
    const std::array<std::string_view, 14> expected_strings{
        "<init>", "Fixture.smali", "I", "III",
        "Laida/c03/corpus/Fixture;", "Ljava/lang/ArithmeticException;",
        "Ljava/lang/Object;", "V", "add", "divisor", "guardedDivide",
        "left", "right", "value"};
    for (std::size_t index = 0; index < expected_strings.size(); ++index) {
        const auto data = le32(bytes, string_offset + index * 4U);
        const auto expected = expected_strings[index];
        if (!span_within(data, expected.size() + 2U, bytes.size()) ||
            bytes[data] != static_cast<std::uint8_t>(expected.size()) ||
            !std::equal(expected.begin(), expected.end(), bytes.begin() + data + 1U) ||
            bytes[data + 1U + expected.size()] != 0U)
            return failure("DEX fixture string identity disagrees with its source corpus");
    }
    const std::array<std::uint32_t, 5> expected_types{2U, 4U, 5U, 6U, 7U};
    for (std::size_t index = 0; index < expected_types.size(); ++index) {
        if (le32(bytes, type_offset + index * 4U) != expected_types[index])
            return failure("DEX fixture type identity disagrees with its source corpus");
    }
    const std::array<std::array<std::uint32_t, 3>, 5> expected_methods{{
        {{1U, 1U, 0U}}, {{1U, 0U, 8U}}, {{1U, 0U, 10U}},
        {{2U, 1U, 0U}}, {{3U, 1U, 0U}}}};
    for (std::size_t index = 0; index < expected_methods.size(); ++index) {
        const auto base = method_offset + index * 8U;
        if (le16(bytes, base) != expected_methods[index][0] ||
            le16(bytes, base + 2U) != expected_methods[index][1] ||
            le32(bytes, base + 4U) != expected_methods[index][2])
            return failure("DEX fixture method identity disagrees with its source corpus");
    }
    if (le32(bytes, class_offset) != 1U ||
        le32(bytes, class_offset + 8U) != 3U ||
        le32(bytes, class_offset + 16U) != 1U ||
        le32(bytes, class_offset + 24U) == 0U)
        return failure("DEX fixture class identity disagrees with its source corpus");
    const auto observed_signature = c03_dex_sha1(bytes, 32U);
    if (!std::equal(observed_signature.begin(), observed_signature.end(),
            bytes.begin() + 12))
        return failure("DEX fixture SHA-1 signature mismatch");
    if (le32(bytes, 8U) != c03_dex_adler32(bytes, 12U))
        return failure("DEX fixture Adler-32 checksum mismatch");
    if (!span_within(layout.map_offset, 4U, bytes.size()))
        return failure("DEX fixture map header exceeds input");
    const auto map_count = le32(bytes, layout.map_offset);
    if (map_count == 0U || map_count > 65536U ||
        !span_within(static_cast<std::uint64_t>(layout.map_offset) + 4U,
            static_cast<std::uint64_t>(map_count) * 12U, bytes.size()))
        return failure("DEX fixture map list range is invalid");
    std::set<std::uint16_t> types;
    std::uint32_t prior_offset = 0U;
    bool first = true;
    struct expected_t { std::uint32_t size; std::uint32_t offset; };
    const std::array<std::pair<std::uint16_t, expected_t>, 8> expected{{
        {0x0000U, {1U, 0U}},
        {0x0001U, {layout.string_count, string_offset}},
        {0x0002U, {layout.type_count, type_offset}},
        {0x0003U, {layout.proto_count, proto_offset}},
        {0x0004U, {field_count, field_offset}},
        {0x0005U, {layout.method_count, method_offset}},
        {0x0006U, {layout.class_count, class_offset}},
        {0x1000U, {1U, layout.map_offset}}
    }};
    std::set<std::uint16_t> matched;
    for (std::uint32_t index = 0; index < map_count; ++index) {
        const auto base = static_cast<std::size_t>(layout.map_offset) + 4U +
            static_cast<std::size_t>(index) * 12U;
        const auto type = le16(bytes, base);
        const auto reserved = le16(bytes, base + 2U);
        const auto count = le32(bytes, base + 4U);
        const auto offset = le32(bytes, base + 8U);
        if (reserved != 0U || count == 0U || !types.insert(type).second ||
            (!first && offset < prior_offset) || offset >= bytes.size())
            return failure("DEX fixture map item is invalid, duplicate, or unordered");
        first = false;
        prior_offset = offset;
        const auto width = fixed_map_width(type);
        if (width != 0U && !span_within(offset,
                static_cast<std::uint64_t>(count) * width, bytes.size()))
            return failure("DEX fixture fixed-width map item exceeds input");
        for (const auto& entry : expected) {
            if (entry.first == type) {
                if (entry.second.size != count || entry.second.offset != offset)
                    return failure("DEX fixture map item disagrees with its header table");
                matched.insert(type);
            }
        }
        if (type == 0x2002U) {
            layout.string_data_offset = offset;
            if (count != layout.string_count)
                return failure("DEX fixture string-data map count is inconsistent");
        } else if (type == 0x2003U) {
            layout.debug_info_offset = offset;
            layout.debug_info_count = count;
        } else if (type == 0x2001U) {
            layout.code_item_offset = offset;
            layout.code_item_count = count;
        } else if (type == 0x2000U) {
            layout.class_data_offset = offset;
            if (count != layout.class_count)
                return failure("DEX fixture class-data map count is inconsistent");
        }
    }
    for (const auto& entry : expected) {
        if (entry.second.size == 0U) {
            if (types.find(entry.first) != types.end())
                return failure("DEX fixture map contains an empty header table");
        } else if (matched.find(entry.first) == matched.end()) {
            return failure("DEX fixture map omits a required header table");
        }
    }
    if (layout.string_data_offset == 0U || layout.debug_info_offset == 0U ||
        layout.code_item_offset == 0U || layout.class_data_offset == 0U ||
        layout.code_item_count != 3U || layout.debug_info_count != 3U)
        return failure("DEX fixture omits required method-bearing data items");
    const std::array<std::uint8_t, 22> expected_debug{
        4U, 0U, 0x0eU, 0U,
        10U, 2U, 12U, 13U, 0x0eU, 1U, 3U, 0x0eU, 0U,
        23U, 2U, 14U, 10U, 0x0eU, 1U, 8U, 0x0eU, 0U};
    if (!span_within(layout.debug_info_offset, expected_debug.size(), bytes.size()) ||
        !std::equal(expected_debug.begin(), expected_debug.end(),
            bytes.begin() + layout.debug_info_offset))
        return failure("DEX fixture debug coordinates disagree with its source corpus");
    result.valid = true;
    return result;
}

bool extract_c03_stored_zip_member(const std::vector<std::uint8_t>& archive,
    std::string_view expected_name, std::vector<std::uint8_t>& member,
    std::string& error)
{
    member.clear();
    if (archive.size() < 30U || le32(archive, 0U) != 0x04034b50U) {
        error = "ZIP fixture local header is absent";
        return false;
    }
    const auto flags = le16(archive, 6U);
    const auto compression = le16(archive, 8U);
    const auto compressed_size = le32(archive, 18U);
    const auto uncompressed_size = le32(archive, 22U);
    const auto name_size = le16(archive, 26U);
    const auto extra_size = le16(archive, 28U);
    if ((flags & 0x2049U) != 0U || (flags & 0x0800U) == 0U ||
        compression != 0U ||
        compressed_size == 0xffffffffU || uncompressed_size == 0xffffffffU ||
        compressed_size != uncompressed_size ||
        !span_within(30U, static_cast<std::uint64_t>(name_size) + extra_size,
            archive.size())) {
        error = "ZIP fixture member is not a bounded unencrypted stored entry";
        return false;
    }
    const std::string_view name(reinterpret_cast<const char*>(archive.data() + 30U),
        name_size);
    if (name != expected_name) {
        error = "ZIP fixture member identity is unexpected";
        return false;
    }
    const auto data_offset = 30ULL + name_size + extra_size;
    if (!span_within(data_offset, compressed_size, archive.size())) {
        error = "ZIP fixture member exceeds the archive";
        return false;
    }
    const auto bounded_data_offset = static_cast<std::size_t>(data_offset);
    const auto bounded_size = static_cast<std::size_t>(compressed_size);
    if (le32(archive, 14U) != crc32(archive.data() + bounded_data_offset,
            bounded_size)) {
        error = "ZIP fixture member CRC-32 mismatch";
        return false;
    }
    member.assign(archive.begin() + static_cast<std::ptrdiff_t>(bounded_data_offset),
        archive.begin() + static_cast<std::ptrdiff_t>(bounded_data_offset + bounded_size));
    error.clear();
    return true;
}
}
