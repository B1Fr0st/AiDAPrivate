#include "authority_surface_ledger.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/mcp/compat/c03_compatibility_registration.hpp"
#include "../../src/core/mcp/compat/ida_contracts_generated.hpp"
#include "../../src/core/mcp/registry/tool_registry.hpp"

#include <Windows.h>
#include <bcrypt.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace aida::tests::c03 {
namespace {

using json = nlohmann::json;
using names_t = std::set<std::string>;

constexpr std::uintmax_t k_maximum_manifest_bytes = 32ULL * 1024ULL * 1024ULL;
constexpr std::uintmax_t k_maximum_source_bytes = 16ULL * 1024ULL * 1024ULL;
constexpr std::string_view k_expected_pinned_archive_sha256 =
    "3F7E7D9F534E3534C191D21251BBF0788DB14376C659488EA61681D48BC8D0F7";

authority_surface_ledger_result_t fail(std::string failure) {
    return {false, std::move(failure)};
}

authority_surface_ledger_result_t complete(authority_surface_ledger_result_t result) {
    aida::analysis::c03_test::assertion_telemetry::record_assertion(
        result.passed,
        result.passed ? std::string_view("authority surface ledger satisfied") :
                        std::string_view(result.failure),
        __FILE__, __LINE__);
    return result;
}

[[noreturn]] void reject(std::string message) {
    throw std::runtime_error(std::move(message));
}

void require(bool condition, std::string message) {
    if (!condition)
        reject(std::move(message));
}

struct algorithm_closer_t {
    void operator()(void* value) const noexcept {
        if (value)
            BCryptCloseAlgorithmProvider(static_cast<BCRYPT_ALG_HANDLE>(value), 0);
    }
};

struct hash_closer_t {
    void operator()(void* value) const noexcept {
        if (value)
            BCryptDestroyHash(static_cast<BCRYPT_HASH_HANDLE>(value));
    }
};

std::string sha256_text(std::string_view value) {
    BCRYPT_ALG_HANDLE raw_algorithm = nullptr;
    auto status = BCryptOpenAlgorithmProvider(
        &raw_algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    require(BCRYPT_SUCCESS(status), "BCrypt SHA-256 provider could not be opened");
    std::unique_ptr<void, algorithm_closer_t> algorithm(raw_algorithm);
    DWORD object_bytes = 0;
    DWORD returned = 0;
    status = BCryptGetProperty(
        raw_algorithm, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&object_bytes), sizeof(object_bytes), &returned, 0);
    require(BCRYPT_SUCCESS(status) && returned == sizeof(object_bytes) && object_bytes != 0,
            "BCrypt SHA-256 object length is invalid");
    std::vector<std::uint8_t> object(object_bytes);
    BCRYPT_HASH_HANDLE raw_hash = nullptr;
    status = BCryptCreateHash(raw_algorithm, &raw_hash, object.data(),
                              static_cast<ULONG>(object.size()), nullptr, 0, 0);
    require(BCRYPT_SUCCESS(status), "BCrypt SHA-256 hash could not be created");
    std::unique_ptr<void, hash_closer_t> hash(raw_hash);
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(value.data());
    auto remaining = value.size();
    while (remaining != 0) {
        const auto chunk = static_cast<ULONG>(std::min<std::size_t>(
            remaining, std::numeric_limits<ULONG>::max()));
        status = BCryptHashData(raw_hash, const_cast<PUCHAR>(bytes), chunk, 0);
        require(BCRYPT_SUCCESS(status), "BCrypt SHA-256 input could not be hashed");
        bytes += chunk;
        remaining -= chunk;
    }
    std::array<std::uint8_t, 32> digest{};
    status = BCryptFinishHash(raw_hash, digest.data(),
                              static_cast<ULONG>(digest.size()), 0);
    require(BCRYPT_SUCCESS(status), "BCrypt SHA-256 digest could not be finalized");
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string result(digest.size() * 2U, '0');
    for (std::size_t index = 0; index < digest.size(); ++index) {
        result[index * 2U] = digits[digest[index] >> 4U];
        result[index * 2U + 1U] = digits[digest[index] & 0x0fU];
    }
    SecureZeroMemory(digest.data(), digest.size());
    hash.reset();
    SecureZeroMemory(object.data(), object.size());
    return result;
}

bool path_is_within(const std::filesystem::path& root,
                    const std::filesystem::path& candidate) {
    const auto root_normal = root.lexically_normal();
    const auto candidate_normal = candidate.lexically_normal();
    auto root_it = root_normal.begin();
    auto candidate_it = candidate_normal.begin();
    while (root_it != root_normal.end()) {
        if (candidate_it == candidate_normal.end() || *root_it != *candidate_it)
            return false;
        ++root_it;
        ++candidate_it;
    }
    return true;
}

std::filesystem::path locate_repository_from(std::filesystem::path cursor) {
    std::error_code ec;
    cursor = std::filesystem::weakly_canonical(std::move(cursor), ec);
    if (ec)
        return {};
    if (std::filesystem::is_regular_file(cursor, ec))
        cursor = cursor.parent_path();
    while (!cursor.empty()) {
        if (std::filesystem::is_regular_file(cursor / "CMakeLists.txt", ec) &&
            std::filesystem::is_regular_file(
                cursor / "tools/c03_authority/authority_surface_ledger.json", ec))
            return cursor;
        const auto parent = cursor.parent_path();
        if (parent == cursor)
            break;
        cursor = parent;
    }
    return {};
}

std::filesystem::path repository_root() {
    if (auto root = locate_repository_from(std::filesystem::path(__FILE__)); !root.empty())
        return root;
    if (auto root = locate_repository_from(std::filesystem::current_path()); !root.empty())
        return root;
    reject("unable to locate the AiDA repository root from the authority harness");
}

std::filesystem::path repository_file(const std::filesystem::path& root,
                                      std::string_view relative) {
    const auto requested = std::filesystem::u8path(std::string(relative));
    require(!requested.empty() && !requested.is_absolute(),
            "authority evidence path must be repository relative: " + std::string(relative));
    std::error_code ec;
    const auto resolved = std::filesystem::weakly_canonical(root / requested, ec);
    require(!ec && path_is_within(root, resolved),
            "authority evidence path escapes the repository: " + std::string(relative));
    require(std::filesystem::is_regular_file(resolved, ec) && !ec,
            "authority evidence file is missing: " + std::string(relative));
    return resolved;
}

std::string read_bounded(const std::filesystem::path& path,
                         std::uintmax_t maximum_bytes) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    require(!ec && size <= maximum_bytes,
            "authority evidence file exceeds its bounded read contract: " + path.u8string());
    std::ifstream stream(path, std::ios::binary);
    require(stream.good(), "authority evidence file could not be opened: " + path.u8string());
    std::string bytes(static_cast<std::size_t>(size), '\0');
    if (!bytes.empty())
        stream.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    require(stream.good() || stream.eof(),
            "authority evidence file could not be read completely: " + path.u8string());
    require(static_cast<std::size_t>(stream.gcount()) == bytes.size() || bytes.empty(),
            "authority evidence file was truncated during its bounded read: " + path.u8string());
    return bytes;
}

json read_json(const std::filesystem::path& path) {
    const auto bytes = read_bounded(path, k_maximum_manifest_bytes);
    try {
        return json::parse(bytes);
    } catch (const json::exception& error) {
        reject("authority JSON is malformed at " + path.u8string() + ": " + error.what());
    }
}

json parse_embedded_json(std::string_view text, std::string_view identity) {
    try {
        return json::parse(text.begin(), text.end());
    } catch (const json::exception& error) {
        reject("generated descriptor JSON is malformed for " + std::string(identity) +
               ": " + error.what());
    }
}

const json& object_member(const json& value, std::string_view key,
                          std::string_view identity) {
    require(value.is_object(), std::string(identity) + " must be a JSON object");
    const auto it = value.find(std::string(key));
    require(it != value.end(), std::string(identity) + " is missing field " + std::string(key));
    return *it;
}

std::string string_member(const json& value, std::string_view key,
                          std::string_view identity, bool allow_empty = false) {
    const auto& member = object_member(value, key, identity);
    require(member.is_string(), std::string(identity) + "." + std::string(key) +
                                " must be a string");
    auto text = member.get<std::string>();
    require(allow_empty || !text.empty(), std::string(identity) + "." + std::string(key) +
                                          " must not be empty");
    return text;
}

std::size_t size_member(const json& value, std::string_view key,
                        std::string_view identity) {
    const auto& member = object_member(value, key, identity);
    require(member.is_number_unsigned() || member.is_number_integer(),
            std::string(identity) + "." + std::string(key) + " must be an integer");
    const auto number = member.get<std::int64_t>();
    require(number >= 0, std::string(identity) + "." + std::string(key) +
                         " must not be negative");
    return static_cast<std::size_t>(number);
}

bool bool_member(const json& value, std::string_view key, std::string_view identity) {
    const auto& member = object_member(value, key, identity);
    require(member.is_boolean(), std::string(identity) + "." + std::string(key) +
                                 " must be boolean");
    return member.get<bool>();
}

names_t names_from(const json& value, std::string_view identity) {
    require(value.is_array(), std::string(identity) + " must be an array");
    names_t result;
    for (const auto& item : value) {
        require(item.is_string() && !item.get_ref<const std::string&>().empty(),
                std::string(identity) + " contains an invalid name");
        require(result.insert(item.get<std::string>()).second,
                std::string(identity) + " contains a duplicate name: " + item.get<std::string>());
    }
    return result;
}

void require_exact_names(const names_t& observed, const names_t& expected,
                         std::string_view identity) {
    if (observed == expected)
        return;
    std::ostringstream message;
    message << identity << " name set differs";
    for (const auto& name : expected) {
        if (!observed.count(name))
            message << " missing=" << name;
    }
    for (const auto& name : observed) {
        if (!expected.count(name))
            message << " unexpected=" << name;
    }
    reject(message.str());
}

names_t set_union_of(const names_t& left, const names_t& right) {
    names_t result;
    std::set_union(left.begin(), left.end(), right.begin(), right.end(),
                   std::inserter(result, result.end()));
    return result;
}

names_t set_intersection_of(const names_t& left, const names_t& right) {
    names_t result;
    std::set_intersection(left.begin(), left.end(), right.begin(), right.end(),
                          std::inserter(result, result.end()));
    return result;
}

names_t set_difference_of(const names_t& left, const names_t& right) {
    names_t result;
    std::set_difference(left.begin(), left.end(), right.begin(), right.end(),
                        std::inserter(result, result.end()));
    return result;
}

bool json_preserves(const json& baseline, const json& current,
                    std::string_view field = {}) {
    if (baseline.type() != current.type())
        return false;
    if (baseline.is_object()) {
        for (auto it = baseline.begin(); it != baseline.end(); ++it) {
            const auto current_it = current.find(it.key());
            if (current_it == current.end() ||
                !json_preserves(it.value(), *current_it, it.key()))
                return false;
        }
        return true;
    }
    if (baseline.is_array()) {
        if (field == "required")
            return baseline == current;
        for (const auto& expected : baseline) {
            if (std::none_of(current.begin(), current.end(), [&](const json& candidate) {
                    return json_preserves(expected, candidate);
                }))
                return false;
        }
        return true;
    }
    return baseline == current;
}

bool parameters_preserved(const json& baseline, const json& current) {
    if (!baseline.is_array() || !current.is_array())
        return false;
    std::map<std::string, const json*> current_by_name;
    for (const auto& parameter : current) {
        if (!parameter.is_object() || !parameter.contains("name") ||
            !parameter.at("name").is_string())
            return false;
        if (!current_by_name.emplace(parameter.at("name").get<std::string>(), &parameter).second)
            return false;
    }
    names_t baseline_names;
    for (const auto& parameter : baseline) {
        if (!parameter.is_object() || !parameter.contains("name") ||
            !parameter.at("name").is_string())
            return false;
        const auto name = parameter.at("name").get<std::string>();
        if (!baseline_names.insert(name).second)
            return false;
        const auto found = current_by_name.find(name);
        if (found == current_by_name.end() || !json_preserves(parameter, *found->second))
            return false;
    }
    for (const auto& [name, parameter] : current_by_name) {
        if (baseline_names.count(name))
            continue;
        if (!parameter->contains("required") || !parameter->at("required").is_boolean() ||
            parameter->at("required").get<bool>())
            return false;
    }
    return true;
}

std::int64_t signed_member(const json& value, std::string_view key,
                           std::string_view identity) {
    const auto& member = object_member(value, key, identity);
    require(member.is_number_integer() || member.is_number_unsigned(),
            std::string(identity) + "." + std::string(key) + " must be an integer");
    try {
        return member.get<std::int64_t>();
    } catch (const json::exception&) {
        reject(std::string(identity) + "." + std::string(key) +
               " is outside the signed integer contract");
    }
}

std::string sha256_lines(const std::vector<std::string>& lines) {
    std::string identity;
    for (std::size_t index = 0; index < lines.size(); ++index) {
        if (index != 0)
            identity.push_back('\n');
        identity += lines[index];
    }
    return sha256_text(identity);
}

std::string sha256_sorted_unique_lines(std::vector<std::string> lines) {
    std::sort(lines.begin(), lines.end());
    lines.erase(std::unique(lines.begin(), lines.end()), lines.end());
    return sha256_lines(lines);
}

std::size_t utf8_sequence_length(std::string_view source, std::size_t offset) {
    require(offset < source.size(), "UTF-8 offset is outside source text");
    const auto lead = static_cast<unsigned char>(source[offset]);
    if (lead <= 0x7FU)
        return 1U;
    std::size_t length = 0;
    std::uint32_t code_point = 0;
    std::uint32_t minimum = 0;
    if ((lead & 0xE0U) == 0xC0U) {
        length = 2U;
        code_point = lead & 0x1FU;
        minimum = 0x80U;
    } else if ((lead & 0xF0U) == 0xE0U) {
        length = 3U;
        code_point = lead & 0x0FU;
        minimum = 0x800U;
    } else if ((lead & 0xF8U) == 0xF0U) {
        length = 4U;
        code_point = lead & 0x07U;
        minimum = 0x10000U;
    } else {
        reject("invalid UTF-8 leading byte at byte offset " + std::to_string(offset));
    }
    require(length <= source.size() - offset,
            "truncated UTF-8 sequence at byte offset " + std::to_string(offset));
    for (std::size_t index = 1U; index < length; ++index) {
        const auto continuation = static_cast<unsigned char>(source[offset + index]);
        require((continuation & 0xC0U) == 0x80U,
                "invalid UTF-8 continuation byte at byte offset " +
                    std::to_string(offset + index));
        code_point = (code_point << 6U) | (continuation & 0x3FU);
    }
    require(code_point >= minimum && code_point <= 0x10FFFFU &&
                !(code_point >= 0xD800U && code_point <= 0xDFFFU),
            "invalid UTF-8 scalar at byte offset " + std::to_string(offset));
    return length;
}

std::size_t utf8_character_offset(std::string_view source,
                                  std::size_t byte_offset) {
    require(byte_offset <= source.size(), "UTF-8 byte offset is outside source text");
    std::size_t characters = 0;
    for (std::size_t offset = 0; offset < byte_offset;) {
        const auto length = utf8_sequence_length(source, offset);
        require(length <= byte_offset - offset,
                "UTF-8 byte offset divides a scalar value");
        offset += length;
        ++characters;
    }
    return characters;
}

std::size_t utf8_byte_offset(std::string_view source,
                             std::size_t character_offset) {
    std::size_t characters = 0;
    std::size_t offset = 0;
    while (offset < source.size() && characters < character_offset) {
        offset += utf8_sequence_length(source, offset);
        ++characters;
    }
    require(characters == character_offset,
            "UTF-8 character offset is outside source text");
    return offset;
}

std::size_t source_line(std::string_view source, std::size_t offset) {
    require(offset <= source.size(), "source offset is outside its source file");
    return static_cast<std::size_t>(std::count(
               source.begin(), source.begin() + static_cast<std::ptrdiff_t>(offset), '\n')) +
           1U;
}

std::size_t matching_index(std::string_view text, std::size_t start,
                           char opening, char closing) {
    require(start < text.size() && text[start] == opening,
            "invalid C++ balanced-range start");
    std::size_t depth = 0;
    for (std::size_t index = start; index < text.size(); ++index) {
        if (text[index] == opening) {
            ++depth;
        } else if (text[index] == closing) {
            require(depth != 0, "invalid C++ balanced-range depth");
            --depth;
            if (depth == 0)
                return index;
        }
    }
    reject("unterminated C++ balanced range at offset " + std::to_string(start));
}

bool cpp_digit_separator(std::string_view source, std::size_t index) {
    if (index == 0U || index + 1U >= source.size() || source[index] != '\'')
        return false;
    auto start = index;
    while (start != 0U) {
        const auto character = static_cast<unsigned char>(source[start - 1U]);
        if (std::isalnum(character) == 0 && character != '_' &&
            character != '\'' && character != '.')
            break;
        --start;
    }
    const auto prefix = std::string(source.substr(start, index - start));
    const auto previous = static_cast<unsigned char>(source[index - 1U]);
    const auto following = static_cast<unsigned char>(source[index + 1U]);
    const auto hexadecimal = [](unsigned char character) {
        return (character >= '0' && character <= '9') ||
               (character >= 'A' && character <= 'F') ||
               (character >= 'a' && character <= 'f');
    };
    static const std::regex hexadecimal_prefix(
        R"(^0[xX][0-9A-Fa-f.pP']*$)");
    if (std::regex_match(prefix, hexadecimal_prefix))
        return hexadecimal(previous) && hexadecimal(following);
    static const std::regex binary_prefix(R"(^0[bB][01']*$)");
    if (std::regex_match(prefix, binary_prefix))
        return (previous == '0' || previous == '1') &&
               (following == '0' || following == '1');
    static const std::regex decimal_prefix(R"(^[0-9][0-9.eE']*$)");
    return std::regex_match(prefix, decimal_prefix) &&
           previous >= '0' && previous <= '9' &&
           following >= '0' && following <= '9';
}

std::string cpp_mask_error_context(std::string_view source, std::size_t byte_offset,
                                   std::string_view label) {
    const auto bounded = std::min(byte_offset, source.size());
    return "source='" + std::string(label) + "' line=" +
           std::to_string(source_line(source, bounded)) +
           " character_offset=" +
           std::to_string(utf8_character_offset(source, bounded)) +
           " byte_offset=" + std::to_string(bounded);
}

std::string cpp_code_mask(std::string_view source, std::string_view label) {
    std::string masked(source);
    std::size_t index = 0;
    while (index < source.size()) {
        const auto current = source[index];
        const auto following = index + 1U < source.size() ? source[index + 1U] : '\0';
        if (current == '/' && following == '/') {
            while (index < source.size() && source[index] != '\r' && source[index] != '\n')
                masked[index++] = ' ';
            continue;
        }
        if (current == '/' && following == '*') {
            const auto comment_start = index;
            masked[index++] = ' ';
            masked[index++] = ' ';
            bool closed = false;
            while (index < source.size()) {
                if (index + 1U < source.size() && source[index] == '*' &&
                    source[index + 1U] == '/') {
                    masked[index++] = ' ';
                    masked[index++] = ' ';
                    closed = true;
                    break;
                }
                if (source[index] != '\r' && source[index] != '\n')
                    masked[index] = ' ';
                ++index;
            }
            require(closed, "unterminated C++ block comment " +
                                cpp_mask_error_context(source, comment_start, label));
            continue;
        }
        if (current == 'R' && following == '"') {
            const auto raw_start = index;
            const auto delimiter_start = index + 2U;
            const auto opening = source.find('(', delimiter_start);
            if (opening != std::string_view::npos && opening >= delimiter_start &&
                opening <= delimiter_start + 16U) {
                const auto delimiter = source.substr(delimiter_start, opening - delimiter_start);
                const bool valid_delimiter = std::none_of(
                    delimiter.begin(), delimiter.end(), [](unsigned char character) {
                        return std::isspace(character) != 0 || character == '\\' ||
                               character == '(' || character == ')';
                    });
                if (valid_delimiter) {
                    const auto terminator = ")" + std::string(delimiter) + "\"";
                    const auto closing = source.find(terminator, opening + 1U);
                    require(closing != std::string_view::npos,
                            "unterminated C++ raw string " +
                                cpp_mask_error_context(source, raw_start, label));
                    const auto end = closing + terminator.size();
                    while (index < end) {
                        if (source[index] != '\r' && source[index] != '\n')
                            masked[index] = ' ';
                        ++index;
                    }
                    continue;
                }
            }
        }
        if (current == '\'' && cpp_digit_separator(source, index)) {
            masked[index] = ' ';
            ++index;
            continue;
        }
        if (current == '"' || current == '\'') {
            const auto literal_start = index;
            const auto quote = current;
            masked[index++] = ' ';
            bool closed = false;
            while (index < source.size()) {
                const auto literal = source[index];
                if (literal == '\\') {
                    masked[index++] = ' ';
                    if (index < source.size()) {
                        if (source[index] != '\r' && source[index] != '\n')
                            masked[index] = ' ';
                        ++index;
                    }
                    continue;
                }
                if (literal != '\r' && literal != '\n')
                    masked[index] = ' ';
                ++index;
                if (literal == quote) {
                    closed = true;
                    break;
                }
            }
            require(closed, "unterminated C++ quoted literal " +
                                cpp_mask_error_context(source, literal_start, label));
            continue;
        }
        ++index;
    }
    return masked;
}

std::string normalized_expression(std::string_view expression) {
    std::string normalized;
    normalized.reserve(expression.size());
    bool pending_space = false;
    for (const auto character : expression) {
        if (std::isspace(static_cast<unsigned char>(character)) != 0) {
            pending_space = !normalized.empty();
            continue;
        }
        if (pending_space)
            normalized.push_back(' ');
        normalized.push_back(character);
        pending_space = false;
    }
    return normalized;
}

struct cpp_namespace_range_t {
    std::string name;
    std::size_t opening = 0;
    std::size_t closing = 0;
};

struct cpp_registrar_t {
    std::string id;
    std::string symbol;
    std::string bare_name;
    std::string name_space;
    std::string parameters;
    std::size_t parameter_count = 0;
    std::string file;
    std::size_t line = 0;
    std::size_t name_offset = 0;
    std::size_t body_start = 0;
    std::size_t body_end = 0;
};

struct cpp_source_t {
    std::string source;
    std::string mask;
};

struct cpp_reachability_sources_t {
    std::map<std::string, cpp_source_t> sources;
    std::vector<cpp_registrar_t> definitions;
};

std::vector<cpp_namespace_range_t> cpp_namespace_ranges(
    std::string_view source, const std::string& mask) {
    static const std::regex pattern(
        R"(\bnamespace\s*([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)?\s*\{)");
    std::vector<cpp_namespace_range_t> result;
    for (std::sregex_iterator it(mask.begin(), mask.end(), pattern), end;
         it != end; ++it) {
        const auto opening = mask.find('{', static_cast<std::size_t>(it->position(0)));
        require(opening != std::string::npos,
                "C++ namespace opening delimiter is unavailable");
        const auto line = source_line(source, static_cast<std::size_t>(it->position(0)));
        result.push_back({
            (*it)[1].matched ? (*it)[1].str()
                             : "<anonymous@" + std::to_string(line) + ">",
            opening, matching_index(mask, opening, '{', '}')});
    }
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        return left.opening < right.opening;
    });
    return result;
}

std::string cpp_namespace_at(
    const std::vector<cpp_namespace_range_t>& ranges, std::size_t offset) {
    std::string result;
    for (const auto& range : ranges) {
        if (!(range.opening < offset && offset < range.closing))
            continue;
        if (!result.empty())
            result += "::";
        result += range.name;
    }
    return result;
}

std::size_t top_level_argument_count(std::string_view expression) {
    std::array<std::size_t, 3> depth{};
    std::size_t count = 0;
    bool has_token = false;
    for (const auto character : expression) {
        switch (character) {
        case '(': ++depth[0]; break;
        case ')': require(depth[0] != 0U, "unbalanced C++ argument parentheses"); --depth[0]; break;
        case '{': ++depth[1]; break;
        case '}': require(depth[1] != 0U, "unbalanced C++ argument braces"); --depth[1]; break;
        case '[': ++depth[2]; break;
        case ']': require(depth[2] != 0U, "unbalanced C++ argument brackets"); --depth[2]; break;
        case ',':
            if (std::all_of(depth.begin(), depth.end(), [](auto value) { return value == 0U; })) {
                require(has_token, "empty top-level C++ argument");
                ++count;
                has_token = false;
                continue;
            }
            break;
        default: break;
        }
        if (std::isspace(static_cast<unsigned char>(character)) == 0)
            has_token = true;
    }
    require(std::all_of(depth.begin(), depth.end(), [](auto value) { return value == 0U; }),
            "unterminated nested C++ argument range");
    if (has_token)
        ++count;
    return count;
}

bool cpp_registrar_declaration(std::string_view mask, std::size_t start,
                               std::size_t closing) {
    auto after = closing + 1U;
    while (after < mask.size() &&
           std::isspace(static_cast<unsigned char>(mask[after])) != 0)
        ++after;
    if (after >= mask.size() || mask[after] != ';')
        return false;
    auto boundary = start;
    while (boundary != 0U) {
        const auto previous = mask[boundary - 1U];
        if (previous == ';' || previous == '{' || previous == '}' ||
            previous == '\r' || previous == '\n')
            break;
        --boundary;
    }
    auto prefix = std::string(mask.substr(boundary, start - boundary));
    const auto first = prefix.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
        return false;
    const auto last = prefix.find_last_not_of(" \t\r\n");
    prefix = prefix.substr(first, last - first + 1U);
    static const std::regex control_pattern(
        R"(^(?:return|co_return|co_await|throw)\b)");
    if (std::regex_search(prefix, control_pattern))
        return false;
    static const std::regex declaration_pattern(
        R"(^(?:(?:extern|static|inline|constexpr|consteval|constinit|friend|virtual|explicit|typename|const|volatile)\s+)*(?:(?:[A-Za-z_]\w*::)*[A-Za-z_]\w*(?:\s*<[^;{}()]*>)?(?:\s*[*&]+)?)(?:\s+(?:(?:[A-Za-z_]\w*::)*[A-Za-z_]\w*(?:\s*<[^;{}()]*>)?(?:\s*[*&]+)?))*$)");
    return std::regex_match(prefix, declaration_pattern);
}

std::vector<cpp_registrar_t> cpp_registrar_definitions(
    const std::string& relative, const std::string& source,
    const std::string& mask) {
    static const std::regex pattern(
        R"(((?:[A-Za-z_]\w*::)*register_[A-Za-z0-9_]+)\s*\()");
    const auto namespaces = cpp_namespace_ranges(source, mask);
    std::vector<cpp_registrar_t> result;
    for (std::sregex_iterator it(mask.begin(), mask.end(), pattern), end;
         it != end; ++it) {
        const auto name_offset = static_cast<std::size_t>(it->position(1));
        if (name_offset != 0) {
            const auto previous = static_cast<unsigned char>(mask[name_offset - 1U]);
            if (std::isalnum(previous) != 0 || previous == '_')
                continue;
        }
        const auto opening = mask.find('(', name_offset + static_cast<std::size_t>(it->length(1)));
        require(opening != std::string::npos,
                "registrar parameter opening delimiter is unavailable");
        const auto closing = matching_index(mask, opening, '(', ')');
        const auto parameters = mask.substr(opening + 1U, closing - opening - 1U);
        auto cursor = closing + 1U;
        while (cursor < mask.size() &&
               std::isspace(static_cast<unsigned char>(mask[cursor])) != 0) {
            ++cursor;
        }
        if (mask.compare(cursor, 8U, "noexcept") == 0) {
            cursor += 8U;
            while (cursor < mask.size() &&
                   std::isspace(static_cast<unsigned char>(mask[cursor])) != 0) {
                ++cursor;
            }
        }
        if (cursor >= mask.size() || mask[cursor] != '{')
            continue;
        const auto declared = (*it)[1].str();
        const auto name_space = cpp_namespace_at(namespaces, name_offset);
        auto symbol = declared;
        if (!name_space.empty() && declared.rfind(name_space + "::", 0) != 0)
            symbol = name_space + "::" + declared;
        const auto line = source_line(source, name_offset);
        result.push_back({
            relative + ":" + std::to_string(line) + ":" + symbol,
            symbol,
            declared.substr(declared.rfind("::") == std::string::npos
                                ? 0U
                                : declared.rfind("::") + 2U),
            name_space,
            normalized_expression(
                std::string_view(source).substr(opening + 1U, closing - opening - 1U)),
            top_level_argument_count(parameters),
            relative,
            line,
            name_offset,
            cursor,
            matching_index(mask, cursor, '{', '}')});
    }
    return result;
}

cpp_reachability_sources_t load_cpp_reachability_sources(
    const std::filesystem::path& root) {
    constexpr std::size_t maximum_files = 4096;
    constexpr std::uintmax_t maximum_file_bytes = 32ULL * 1024ULL * 1024ULL;
    constexpr std::uintmax_t maximum_total_bytes = 512ULL * 1024ULL * 1024ULL;
    const auto source_root = root / "src/standalone/src/core";
    std::vector<std::filesystem::path> paths;
    std::uintmax_t total_bytes = 0;
    std::error_code ec;
    for (std::filesystem::recursive_directory_iterator it(
             source_root, std::filesystem::directory_options::skip_permission_denied, ec), end;
         it != end; it.increment(ec)) {
        require(!ec, "C++ reachability source traversal failed");
        if (!it->is_regular_file(ec) || ec || it->path().extension() != ".cpp") {
            ec.clear();
            continue;
        }
        paths.push_back(it->path());
        require(paths.size() <= maximum_files,
                "C++ reachability source count exceeds policy");
        const auto bytes = it->file_size(ec);
        require(!ec && bytes <= maximum_file_bytes &&
                    total_bytes <= maximum_total_bytes - bytes,
                "C++ reachability sources exceed bounded size policy");
        total_bytes += bytes;
    }
    require(!paths.empty(), "C++ reachability source inventory is empty");
    std::sort(paths.begin(), paths.end());

    cpp_reachability_sources_t result;
    for (const auto& path : paths) {
        const auto relative = std::filesystem::relative(path, root, ec).generic_u8string();
        require(!ec && !relative.empty(),
                "C++ reachability source path is not repository relative");
        const auto source = read_bounded(repository_file(root, relative),
                                         maximum_file_bytes);
        utf8_character_offset(source, source.size());
        if (source.find("register_") == std::string::npos)
            continue;
        auto unit = cpp_source_t{source, cpp_code_mask(source, relative)};
        auto definitions = cpp_registrar_definitions(
            relative, unit.source, unit.mask);
        result.definitions.insert(
            result.definitions.end(),
            std::make_move_iterator(definitions.begin()),
            std::make_move_iterator(definitions.end()));
        require(result.sources.emplace(relative, std::move(unit)).second,
                "duplicate C++ reachability source path");
    }
    require(!result.definitions.empty(), "no C++ MCP registrar definitions were found");
    names_t ids;
    for (const auto& definition : result.definitions) {
        require(ids.insert(definition.id).second,
                "ambiguous C++ registrar definition identity: " + definition.id);
    }
    return result;
}

const cpp_registrar_t& resolve_cpp_registrar_target(
    const cpp_registrar_t& caller, std::string_view callee,
    const std::vector<cpp_registrar_t>& definitions,
    std::size_t argument_count) {
    std::vector<std::string> candidates;
    auto name_space = caller.name_space;
    while (!name_space.empty()) {
        candidates.push_back(name_space + "::" + std::string(callee));
        const auto separator = name_space.rfind("::");
        name_space = separator == std::string::npos
            ? std::string()
            : name_space.substr(0, separator);
    }
    candidates.emplace_back(callee);
    for (const auto& candidate : candidates) {
        std::vector<const cpp_registrar_t*> matches;
        for (const auto& definition : definitions) {
            if (definition.symbol == candidate &&
                definition.parameter_count == argument_count)
                matches.push_back(&definition);
        }
        require(matches.size() <= 1U,
                "ambiguous registrar definition for " + std::string(callee) +
                    " from " + caller.id);
        if (matches.size() == 1U)
            return *matches.front();
    }
    const auto separator = callee.rfind("::");
    const auto bare = std::string(callee.substr(
        separator == std::string_view::npos ? 0U : separator + 2U));
    std::vector<const cpp_registrar_t*> matches;
    for (const auto& definition : definitions) {
        const bool match = callee.find("::") != std::string_view::npos
            ? definition.symbol == callee ||
                  (definition.symbol.size() > callee.size() + 2U &&
                   definition.symbol.compare(
                       definition.symbol.size() - callee.size(), callee.size(), callee) == 0 &&
                   definition.symbol[definition.symbol.size() - callee.size() - 1U] == ':')
            : definition.bare_name == bare;
        if (match && definition.parameter_count == argument_count)
            matches.push_back(&definition);
    }
    require(matches.size() == 1U,
            "unresolved or ambiguous registrar edge " + std::string(callee) +
                " from " + caller.id + " candidates=" +
                std::to_string(matches.size()));
    return *matches.front();
}

json cpp_registrar_calls(
    const cpp_registrar_t& caller, const cpp_source_t& unit,
    const std::vector<cpp_registrar_t>& definitions,
    const names_t& terminal_offsets,
    const std::map<std::string, json>& explicit_edges) {
    static const std::regex registrar_pattern(
        R"(((?:[A-Za-z_]\w*::)*(?:register|replace)_[A-Za-z0-9_]+)\s*\()");
    const auto body_start = caller.body_start + 1U;
    const auto body = unit.mask.substr(body_start, caller.body_end - body_start);
    json calls = json::array();
    for (std::sregex_iterator it(body.begin(), body.end(), registrar_pattern), end;
         it != end; ++it) {
        const auto callee = (*it)[1].str();
        const auto absolute = body_start + static_cast<std::size_t>(it->position(1));
        const auto terminal_key = caller.file + ":" + std::to_string(absolute);
        const auto previous_terminal_key = absolute == 0U
            ? std::string()
            : caller.file + ":" + std::to_string(absolute - 1U);
        if (terminal_offsets.count(terminal_key) != 0U ||
            terminal_offsets.count(previous_terminal_key) != 0U)
            continue;
        const auto opening = unit.mask.find('(', absolute + callee.size());
        require(opening != std::string::npos,
                "registrar call opening delimiter is unavailable");
        const auto closing = matching_index(unit.mask, opening, '(', ')');
        require(!cpp_registrar_declaration(unit.mask, absolute, closing),
                "registrar declaration is forbidden in reachable code: " + callee +
                    " from " + caller.id);
        if (const auto explicit_it = explicit_edges.find(terminal_key);
            explicit_it != explicit_edges.end()) {
            const auto& edge = explicit_it->second;
            require(string_member(edge, "caller_id", "explicit registrar edge") == caller.id,
                    "explicit registrar edge has the wrong enclosing owner at " +
                        terminal_key);
            calls.push_back({
                {"caller_id", caller.id},
                {"callee_id", string_member(edge, "callee_id", "explicit registrar edge")},
                {"callee_symbol", string_member(edge, "callee_symbol", "explicit registrar edge")},
                {"file", caller.file},
                {"line", source_line(unit.source, absolute)},
                {"character_offset", utf8_character_offset(unit.source, absolute)},
                {"expression", string_member(edge, "expression", "explicit registrar edge")}
            });
            continue;
        }
        if (absolute != 0U) {
            const auto immediate = static_cast<unsigned char>(
                unit.mask[absolute - 1U]);
            if (std::isalnum(immediate) != 0 || immediate == '_')
                continue;
            auto predecessor = absolute;
            while (predecessor != 0U &&
                   std::isspace(static_cast<unsigned char>(
                       unit.mask[predecessor - 1U])) != 0)
                --predecessor;
            const auto previous = predecessor == 0U
                ? static_cast<unsigned char>(0)
                : static_cast<unsigned char>(unit.mask[predecessor - 1U]);
            require(previous != '.' && previous != '>' && previous != ':',
                    "indirect registrar edge is not source-resolvable from " + caller.id);
        }
        const auto argument_count = top_level_argument_count(
            std::string_view(unit.mask).substr(
                opening + 1U, closing - opening - 1U));
        const auto& target = resolve_cpp_registrar_target(
            caller, callee, definitions, argument_count);
        calls.push_back({
            {"caller_id", caller.id},
            {"callee_id", target.id},
            {"callee_symbol", target.symbol},
            {"file", caller.file},
            {"line", source_line(unit.source, absolute)},
            {"character_offset", utf8_character_offset(unit.source, absolute)},
            {"expression", normalized_expression(
                std::string_view(unit.source).substr(absolute, closing - absolute + 1U))}
        });
    }
    return calls;
}

struct derived_reachability_t {
    json production_entry;
    json registrars;
    json edges;
    std::unordered_map<std::string, std::vector<std::string>> chains;
    std::unordered_map<std::string, const cpp_registrar_t*> definitions_by_id;
};

derived_reachability_t derive_reachability(
    const cpp_reachability_sources_t& sources,
    const names_t& terminal_offsets) {
    std::vector<const cpp_registrar_t*> roots;
    for (const auto& definition : sources.definitions) {
        if (definition.symbol == "mcp_standalone::register_standalone_tools")
            roots.push_back(&definition);
    }
    require(roots.size() == 1U,
            "production MCP root registrar definition count is not exactly one");
    const auto* root_registrar = roots.front();

    const auto entry_file = std::string(
        "src/standalone/src/core/ai/standalone_chat.cpp");
    const auto entry_it = sources.sources.find(entry_file);
    require(entry_it != sources.sources.end(),
            "standalone production MCP entry source is unavailable");
    const auto entry_token = std::string(
        "mcp_standalone::register_standalone_tools");
    std::vector<std::size_t> entry_offsets;
    for (std::size_t offset = entry_it->second.mask.find(entry_token);
         offset != std::string::npos;
         offset = entry_it->second.mask.find(entry_token, offset + entry_token.size())) {
        auto opening = entry_it->second.mask.find('(', offset + entry_token.size());
        if (opening == std::string::npos)
            continue;
        const auto closing = matching_index(entry_it->second.mask, opening, '(', ')');
        const auto expression = normalized_expression(
            std::string_view(entry_it->second.source).substr(
                offset, closing - offset + 1U));
        if (expression == "mcp_standalone::register_standalone_tools(s_mcp_server)")
            entry_offsets.push_back(offset);
    }
    require(entry_offsets.size() == 1U,
            "standalone production MCP initialization call is not unique code");
    const auto entry_offset = entry_offsets.front();
    const auto entry_opening = entry_it->second.mask.find(
        '(', entry_offset + entry_token.size());
    const auto entry_closing = matching_index(
        entry_it->second.mask, entry_opening, '(', ')');

    derived_reachability_t result;
    result.production_entry = {
        {"file", entry_file},
        {"line", source_line(entry_it->second.source, entry_offset)},
        {"character_offset", utf8_character_offset(
            entry_it->second.source, entry_offset)},
        {"expression", normalized_expression(
            std::string_view(entry_it->second.source).substr(
                entry_offset, entry_closing - entry_offset + 1U))},
        {"root_registrar_id", root_registrar->id},
        {"root_registrar_symbol", root_registrar->symbol}
    };

    for (const auto& definition : sources.definitions)
        result.definitions_by_id.emplace(definition.id, &definition);
    std::map<std::string, const cpp_registrar_t*> reachable;
    std::unordered_map<std::string, std::string> parents;
    result.chains.emplace(root_registrar->id,
                          std::vector<std::string>{root_registrar->id});
    reachable.emplace(root_registrar->id, root_registrar);
    std::deque<const cpp_registrar_t*> queue{root_registrar};
    json edges = json::array();
    while (!queue.empty()) {
        const auto* caller = queue.front();
        queue.pop_front();
        const auto source_it = sources.sources.find(caller->file);
        require(source_it != sources.sources.end(),
                "reachable registrar source cache is unavailable: " + caller->file);
        const auto calls = cpp_registrar_calls(
            *caller, source_it->second, sources.definitions, terminal_offsets,
            {});
        names_t local_targets;
        for (const auto& edge : calls) {
            const auto target_id = string_member(edge, "callee_id", "derived registrar edge");
            require(local_targets.insert(target_id).second,
                    "registrar invokes one child more than once: " + target_id);
            require(target_id != root_registrar->id && parents.count(target_id) == 0U,
                    "registrar graph has a cycle or multiple production parents: " + target_id);
            const auto definition_it = result.definitions_by_id.find(target_id);
            require(definition_it != result.definitions_by_id.end(),
                    "resolved registrar target identity is unavailable: " + target_id);
            parents.emplace(target_id, caller->id);
            auto chain = result.chains.at(caller->id);
            chain.push_back(target_id);
            result.chains.emplace(target_id, std::move(chain));
            reachable.emplace(target_id, definition_it->second);
            edges.push_back(edge);
            queue.push_back(definition_it->second);
        }
    }

    result.registrars = json::array();
    for (const auto& [identifier, definition] : reachable) {
        json parent = nullptr;
        if (identifier != root_registrar->id)
            parent = parents.at(identifier);
        result.registrars.push_back({
            {"id", identifier},
            {"symbol", definition->symbol},
            {"file", definition->file},
            {"line", definition->line},
            {"body_start", utf8_character_offset(
                sources.sources.at(definition->file).source, definition->body_start)},
            {"body_end", utf8_character_offset(
                sources.sources.at(definition->file).source, definition->body_end)},
            {"parent_id", parent},
            {"chain", result.chains.at(identifier)}
        });
    }
    std::vector<json> sorted_edges(edges.begin(), edges.end());
    std::sort(sorted_edges.begin(), sorted_edges.end(), [](const auto& left, const auto& right) {
        return std::tuple{
                   left.at("caller_id").get<std::string>(),
                   left.at("callee_id").get<std::string>(),
                   left.at("file").get<std::string>(),
                   left.at("line").get<std::size_t>()} <
               std::tuple{
                   right.at("caller_id").get<std::string>(),
                   right.at("callee_id").get<std::string>(),
                   right.at("file").get<std::string>(),
                   right.at("line").get<std::size_t>()};
    });
    result.edges = json::array();
    for (auto& edge : sorted_edges)
        result.edges.push_back(std::move(edge));
    return result;
}

const cpp_registrar_t& select_unique_definition(
    const cpp_reachability_sources_t& sources, std::string_view file,
    std::string_view bare_name, const std::regex& parameter_pattern,
    std::string_view identity) {
    std::vector<const cpp_registrar_t*> matches;
    for (const auto& definition : sources.definitions) {
        if (definition.file == file && definition.bare_name == bare_name &&
            std::regex_search(definition.parameters, parameter_pattern)) {
            matches.push_back(&definition);
        }
    }
    require(matches.size() == 1U,
            std::string(identity) + " definition count is " +
                std::to_string(matches.size()) + ", expected one");
    return *matches.front();
}

json unique_owned_code_call(
    const cpp_reachability_sources_t& sources, std::string_view file,
    const std::regex& pattern, std::string_view identity,
    const cpp_registrar_t& expected_caller) {
    const auto unit_it = sources.sources.find(std::string(file));
    require(unit_it != sources.sources.end(),
            std::string(identity) + " source is unavailable");
    const auto& unit = unit_it->second;
    std::vector<std::smatch> matches;
    for (std::sregex_iterator it(unit.mask.begin(), unit.mask.end(), pattern), end;
         it != end; ++it) {
        matches.push_back(*it);
    }
    require(matches.size() == 1U,
            std::string(identity) + " must have exactly one code occurrence, observed " +
                std::to_string(matches.size()));
    const auto expression_offset = static_cast<std::size_t>(matches.front().position(0));
    const auto opening = unit.mask.find('(', expression_offset);
    require(opening != std::string::npos,
            std::string(identity) + " call opening delimiter is unavailable");
    const auto closing = matching_index(unit.mask, opening, '(', ')');
    const auto expression_mask = unit.mask.substr(
        expression_offset, closing - expression_offset + 1U);
    static const std::regex registrar_pattern(
        R"(\b(?:register|replace)_[A-Za-z0-9_]+\s*\()");
    std::smatch registrar_match;
    require(std::regex_search(expression_mask, registrar_match, registrar_pattern),
            std::string(identity) + " does not contain a registrar-like call");
    const auto registrar_offset = expression_offset +
        static_cast<std::size_t>(registrar_match.position(0));
    std::vector<const cpp_registrar_t*> owners;
    for (const auto& definition : sources.definitions) {
        if (definition.file == file && definition.body_start < expression_offset &&
            expression_offset < definition.body_end) {
            owners.push_back(&definition);
        }
    }
    require(owners.size() == 1U && owners.front()->id == expected_caller.id,
            std::string(identity) + " has an invalid enclosing definition");
    return {
        {"file", file},
        {"line", source_line(unit.source, expression_offset)},
        {"character_offset", utf8_character_offset(unit.source, registrar_offset)},
        {"expression", normalized_expression(
            std::string_view(unit.source).substr(
                expression_offset, closing - expression_offset + 1U))},
        {"caller_id", expected_caller.id},
        {"caller_symbol", expected_caller.symbol}
    };
}

struct generated_route_t {
    json route;
    std::unordered_map<std::string, json> bindings_by_name;
};

generated_route_t derive_generated_route(
    const cpp_reachability_sources_t& sources,
    const cpp_registrar_t& root_registrar,
    const json& compatibility_rows,
    const json& direct_edges,
    const names_t& registration_terminal_offsets) {
    const std::string standalone_tools =
        "src/standalone/src/core/mcp/mcp_standalone_tools.cpp";
    const std::string server_file =
        "src/standalone/src/core/mcp/mcp_standalone.cpp";
    const std::string registration_file =
        "src/standalone/src/core/mcp/compat/c03_compatibility_registration.cpp";
    const std::string integration_file =
        "src/standalone/src/core/mcp/compat/mcp_server_integration.cpp";

    const auto& server_bridge = select_unique_definition(
        sources, server_file, "register_c03_compatibility_tools",
        std::regex(R"(server_t\s*&)") , "C03 server bridge");
    const auto& config_bridge = select_unique_definition(
        sources, registration_file, "register_c03_compatibility_tools",
        std::regex(R"(tool_registry_t\s*&.*c03_compatibility_runtime_config_t)"),
        "C03 runtime-config bridge");
    const auto& wave_registrar = select_unique_definition(
        sources, registration_file, "register_wave_c_compatibility_tools",
        std::regex(R"(tool_registry_t\s*&.*c03_compatibility_runtime_config_t)"),
        "C03 Wave C registrar");
    const auto& generated_registrar = select_unique_definition(
        sources, integration_file, "register_generated_tools",
        std::regex(R"(^$)"), "C03 generated registrar");
    const auto& extension_registrar = select_unique_definition(
        sources, integration_file, "register_extension_tools",
        std::regex(R"(^$)"), "C03 extension registrar");
    const auto& entry_registrar = select_unique_definition(
        sources, integration_file, "register_entry",
        std::regex(R"(shared_ptr<mcp_server_integration_t>.*std::string\s*&)") ,
        "C03 per-name registrar");

    struct route_specification_t {
        std::string file;
        std::regex pattern;
        std::string identity;
        const cpp_registrar_t* caller;
        const cpp_registrar_t* callee;
    };
    const std::vector<route_specification_t> specifications = {
        {standalone_tools,
         std::regex(R"(\bregister_c03_compatibility_tools\s*\(\s*srv\s*\))"),
         "C03 compatibility root registrar edge", &root_registrar, &server_bridge},
        {server_file,
         std::regex(R"(\bregister_c03_compatibility_tools\s*\(\s*server\.registry\s*\(\s*\)\s*,\s*make_application_c03_compatibility_runtime_config\s*\(\s*\)\s*\))"),
         "C03 compatibility server bridge edge", &server_bridge, &config_bridge},
        {registration_file,
         std::regex(R"(\bregister_wave_c_compatibility_tools\s*\(\s*registry\s*,\s*std::move\s*\(\s*config\s*\)\s*\))"),
         "C03 compatibility wave registrar edge", &config_bridge, &wave_registrar},
        {registration_file,
         std::regex(R"(\bintegration\s*->\s*register_generated_tools\s*\(\s*\))"),
         "C03 generated compatibility registrar edge", &wave_registrar, &generated_registrar},
        {registration_file,
         std::regex(R"(\bintegration\s*->\s*register_extension_tools\s*\(\s*\))"),
         "C03 extension registrar edge", &wave_registrar, &extension_registrar},
        {integration_file,
         std::regex(R"(\bimpl_\s*->\s*register_entry\s*\(\s*owner\s*,\s*name\s*\))"),
         "C03 generated per-name registrar edge", &generated_registrar, &entry_registrar},
        {integration_file,
         std::regex(R"(\bimpl_\s*->\s*register_entry\s*\(\s*owner\s*,\s*std::string\s*\(\s*name\s*\)\s*\))"),
         "C03 extension per-name registrar edge", &extension_registrar, &entry_registrar}
    };

    json edges = json::array();
    for (const auto& specification : specifications) {
        auto call = unique_owned_code_call(
            sources, specification.file, specification.pattern,
            specification.identity, *specification.caller);
        call["callee_id"] = specification.callee->id;
        call["callee_symbol"] = specification.callee->symbol;
        edges.push_back(std::move(call));
    }

    const auto terminal_call = [&](const std::regex& pattern,
                                   std::string_view identity) {
        return unique_owned_code_call(
            sources, integration_file, pattern, identity, entry_registrar);
    };
    json terminal_operations = json::array({
        terminal_call(
            std::regex(R"(\bstate\.registry\s*->\s*replace_tool\s*\(\s*std::move\s*\(\s*tool\s*\)\s*\))"),
            "C03 replacement terminal registration"),
        terminal_call(
            std::regex(R"(\bstate\.registry\s*->\s*register_tool\s*\(\s*std::move\s*\(\s*tool\s*\)\s*\))"),
            "C03 insertion terminal registration")
    });

    std::map<std::string, json> explicit_edges;
    for (const auto& edge : edges) {
        const auto file = string_member(edge, "file", "generated route edge");
        const auto unit_it = sources.sources.find(file);
        require(unit_it != sources.sources.end(),
                "generated route edge source is unavailable");
        const auto character_offset = size_member(
            edge, "character_offset", "generated route edge");
        const auto byte_offset = utf8_byte_offset(
            unit_it->second.source, character_offset);
        require(explicit_edges.emplace(
                    file + ":" + std::to_string(byte_offset), edge).second,
                "generated route contains a duplicate explicit registrar offset");
    }
    auto route_terminal_offsets = registration_terminal_offsets;
    for (const auto& operation : terminal_operations) {
        const auto file = string_member(
            operation, "file", "generated terminal operation");
        const auto unit_it = sources.sources.find(file);
        require(unit_it != sources.sources.end(),
                "generated terminal operation source is unavailable");
        const auto character_offset = size_member(
            operation, "character_offset", "generated terminal operation");
        route_terminal_offsets.insert(
            file + ":" + std::to_string(utf8_byte_offset(
                unit_it->second.source, character_offset)));
    }

    const std::array<const cpp_registrar_t*, 7> node_definitions = {
        &root_registrar, &server_bridge, &config_bridge, &wave_registrar,
        &generated_registrar, &extension_registrar, &entry_registrar
    };
    for (const auto* definition : node_definitions) {
        const auto unit_it = sources.sources.find(definition->file);
        require(unit_it != sources.sources.end(),
                "generated route registrar source is unavailable: " +
                    definition->file);
        const auto observed = cpp_registrar_calls(
            *definition, unit_it->second, sources.definitions,
            route_terminal_offsets, explicit_edges);
        std::vector<std::string> observed_lines;
        for (const auto& edge : observed) {
            observed_lines.push_back(
                string_member(edge, "caller_id", "observed route edge") + "\t" +
                string_member(edge, "callee_id", "observed route edge") + "\t" +
                string_member(edge, "file", "observed route edge") + "\t" +
                std::to_string(size_member(
                    edge, "character_offset", "observed route edge")));
        }
        std::vector<std::string> expected_lines;
        for (const auto& edge : edges) {
            if (string_member(edge, "caller_id", "generated route edge") ==
                definition->id) {
                expected_lines.push_back(
                    definition->id + "\t" +
                    string_member(edge, "callee_id", "generated route edge") + "\t" +
                    string_member(edge, "file", "generated route edge") + "\t" +
                    std::to_string(size_member(
                        edge, "character_offset", "generated route edge")));
            }
        }
        if (definition->id == root_registrar.id) {
            for (const auto& edge : direct_edges) {
                if (string_member(edge, "caller_id", "direct registrar edge") ==
                    definition->id) {
                    expected_lines.push_back(
                        definition->id + "\t" +
                        string_member(edge, "callee_id", "direct registrar edge") + "\t" +
                        string_member(edge, "file", "direct registrar edge") + "\t" +
                        std::to_string(size_member(
                            edge, "character_offset", "direct registrar edge")));
                }
            }
        }
        std::sort(observed_lines.begin(), observed_lines.end());
        std::sort(expected_lines.begin(), expected_lines.end());
        require(observed_lines == expected_lines,
                "generated registrar body has an unclassified or missing edge: " +
                    definition->id);
    }

    std::map<std::string, names_t> route_parents;
    for (const auto& edge : edges) {
        route_parents[string_member(edge, "callee_id", "generated route edge")].insert(
            string_member(edge, "caller_id", "generated route edge"));
    }
    const names_t shared_parents = {
        generated_registrar.id, extension_registrar.id
    };
    for (const auto* definition : node_definitions) {
        const auto parents = route_parents[definition->id];
        if (definition->id == root_registrar.id) {
            require(parents.empty(), "generated route root has a production parent");
        } else if (definition->id == entry_registrar.id) {
            require(parents == shared_parents,
                    "generated route shared terminal has invalid parents");
        } else {
            require(parents.size() == 1U,
                    "generated route has a cycle, missing parent, or multiple parent");
        }
    }

    json nodes = json::array();
    for (const auto* definition : node_definitions) {
        nodes.push_back({
            {"id", definition->id},
            {"symbol", definition->symbol},
            {"file", definition->file},
            {"line", definition->line},
            {"body_start", utf8_character_offset(
                sources.sources.at(definition->file).source, definition->body_start)},
            {"body_end", utf8_character_offset(
                sources.sources.at(definition->file).source, definition->body_end)},
            {"parameters", definition->parameters}
        });
    }

    const std::vector<std::string> base_chain = {
        root_registrar.id, server_bridge.id, config_bridge.id, wave_registrar.id
    };
    auto compatibility_chain = base_chain;
    compatibility_chain.push_back(generated_registrar.id);
    compatibility_chain.push_back(entry_registrar.id);
    auto extension_chain = base_chain;
    extension_chain.push_back(extension_registrar.id);
    extension_chain.push_back(entry_registrar.id);

    generated_route_t result;
    json bindings = json::array();
    names_t binding_names;
    std::vector<std::string> binding_lines;
    require(compatibility_rows.is_array() && compatibility_rows.size() == 92U,
            "generated compatibility binding source must contain 92 rows");
    for (const auto& row : compatibility_rows) {
        const auto name = string_member(row, "name", "generated compatibility binding");
        require(binding_names.insert(name).second,
                "generated compatibility binding is duplicated: " + name);
        const auto descriptor = string_member(
            row, "descriptor_source", "generated compatibility binding");
        const bool extension = descriptor.find("#wave_c_extension_binding") !=
                               std::string::npos;
        const auto& chain = extension ? extension_chain : compatibility_chain;
        json binding = {
            {"name", name},
            {"branch", extension ? "extension" : "generated_compatibility"},
            {"registrar_id", entry_registrar.id},
            {"registrar_symbol", entry_registrar.symbol},
            {"chain", chain},
            {"chain_sha256", sha256_lines(chain)}
        };
        result.bindings_by_name.emplace(name, binding);
        binding_lines.push_back(
            name + "\t" + string_member(binding, "branch", name) + "\t" +
            entry_registrar.id + "\t" + string_member(binding, "chain_sha256", name));
        bindings.push_back(std::move(binding));
    }
    std::sort(bindings.begin(), bindings.end(), [](const auto& left, const auto& right) {
        return left.at("name").get_ref<const std::string&>() <
               right.at("name").get_ref<const std::string&>();
    });
    require(std::count_if(bindings.begin(), bindings.end(), [](const auto& binding) {
                return binding.at("branch") == "generated_compatibility";
            }) == 88 &&
                std::count_if(bindings.begin(), bindings.end(), [](const auto& binding) {
                    return binding.at("branch") == "extension";
                }) == 4,
            "generated compatibility reachability partition is invalid");

    std::vector<std::string> route_lines;
    for (const auto& node : nodes) {
        route_lines.push_back(
            "R\t" + string_member(node, "id", "generated route node") + "\t" +
            string_member(node, "symbol", "generated route node") + "\t" +
            string_member(node, "file", "generated route node") + "\t" +
            std::to_string(size_member(node, "line", "generated route node")));
    }
    for (const auto& edge : edges) {
        route_lines.push_back(
            "E\t" + string_member(edge, "caller_id", "generated route edge") + "\t" +
            string_member(edge, "callee_id", "generated route edge") + "\t" +
            string_member(edge, "file", "generated route edge") + "\t" +
            std::to_string(size_member(edge, "line", "generated route edge")) + "\t" +
            std::to_string(size_member(edge, "character_offset", "generated route edge")) + "\t" +
            string_member(edge, "expression", "generated route edge"));
    }
    for (const auto& operation : terminal_operations) {
        route_lines.push_back(
            "T\t" + string_member(operation, "caller_id", "generated terminal operation") + "\t" +
            string_member(operation, "file", "generated terminal operation") + "\t" +
            std::to_string(size_member(operation, "line", "generated terminal operation")) + "\t" +
            std::to_string(size_member(operation, "character_offset", "generated terminal operation")) + "\t" +
            string_member(operation, "expression", "generated terminal operation"));
    }
    std::sort(binding_lines.begin(), binding_lines.end());
    result.route = {
        {"node_count", nodes.size()},
        {"edge_count", edges.size()},
        {"terminal_operation_count", terminal_operations.size()},
        {"binding_count", bindings.size()},
        {"generated_compatibility_count", 88},
        {"extension_count", 4},
        {"shared_terminal_definition_id", entry_registrar.id},
        {"shared_terminal_parent_ids", std::vector<std::string>(
            shared_parents.begin(), shared_parents.end())},
        {"nodes", nodes},
        {"edges", edges},
        {"terminal_operations", terminal_operations},
        {"bindings", bindings},
        {"route_sha256", sha256_sorted_unique_lines(route_lines)},
        {"binding_sha256", sha256_sorted_unique_lines(binding_lines)}
    };
    return result;
}

std::string effect_name(aida::standalone::mcp::compat::contract_effect_t effect) {
    using effect_t = aida::standalone::mcp::compat::contract_effect_t;
    switch (effect) {
    case effect_t::workspace_read: return "workspace_read";
    case effect_t::workspace_checkpoint: return "workspace_checkpoint";
    case effect_t::workspace_overlay_mutation: return "workspace_overlay_mutation";
    case effect_t::debugger_read: return "debugger_read";
    case effect_t::debugger_control: return "debugger_control";
    case effect_t::debugger_write: return "debugger_write";
    case effect_t::isolated_python: return "isolated_python";
    case effect_t::registry_read: return "registry_read";
    }
    reject("generated descriptor contains an invalid effect ordinal");
}

std::string lock_name(aida::standalone::mcp::compat::contract_lock_t lock) {
    using lock_t = aida::standalone::mcp::compat::contract_lock_t;
    switch (lock) {
    case lock_t::workspace_shared: return "workspace_shared";
    case lock_t::workspace_checkpoint: return "workspace_checkpoint";
    case lock_t::workspace_overlay_transaction: return "workspace_overlay_transaction";
    case lock_t::debugger_lane: return "debugger_lane";
    case lock_t::python_worker: return "python_worker";
    case lock_t::registry_read: return "registry_read";
    }
    reject("generated descriptor contains an invalid lock ordinal");
}

struct authority_contract_t {
    names_t upstream;
    names_t required;
    names_t extensions;
    names_t union_names;
};

authority_contract_t verify_authority_ledger(const json& ledger,
                                             const std::filesystem::path& root) {
    require(string_member(ledger, "schema", "authority ledger") ==
                "aida.c03.authority-surface-ledger.v2",
            "authority ledger schema identity mismatch");
    const auto& authority = object_member(ledger, "authority", "authority ledger");
    const auto& archive = object_member(authority, "pinned_ida_pro_mcp_archive", "authority");
    require(string_member(archive, "sha256", "pinned archive") ==
                k_expected_pinned_archive_sha256,
            "authority ledger pinned archive fingerprint mismatch");
    require(string_member(archive, "version", "pinned archive") == "2.0.0" &&
                string_member(archive, "license", "pinned archive") == "MIT" &&
                string_member(archive, "inspection_mode", "pinned archive") ==
                    "zip_data_only_no_archive_code_execution",
            "authority ledger pinned archive provenance mismatch");

    const auto& compatibility = object_member(ledger, "mcp_compatibility", "authority ledger");
    authority_contract_t contract;
    contract.upstream = names_from(
        object_member(compatibility, "upstream_tool_names", "mcp compatibility"),
        "upstream tool names");
    contract.required = names_from(
        object_member(compatibility, "required_compatibility_names", "mcp compatibility"),
        "required compatibility names");
    contract.extensions = names_from(
        object_member(compatibility, "preserved_aida_extensions", "mcp compatibility"),
        "preserved AiDA extensions");
    require(size_member(compatibility, "upstream_tool_count", "mcp compatibility") == 88U &&
                contract.upstream.size() == 88U,
            "upstream compatibility authority must contain 88 unique names");
    const auto exclusions = names_from(
        object_member(compatibility, "explicit_excluded_tools", "mcp compatibility"),
        "explicit excluded tools");
    require(exclusions == names_t{"py_eval"} && contract.upstream.count("py_eval") == 1U,
            "py_eval must be the only excluded pinned upstream tool");
    const auto proxy_local = names_from(
        object_member(compatibility, "proxy_local_compatibility_tools", "mcp compatibility"),
        "proxy-local compatibility tools");
    require(proxy_local == names_t{"list_instances"},
            "list_instances must be the only proxy-local compatibility tool");
    auto derived_required = contract.upstream;
    derived_required.erase("py_eval");
    derived_required.insert("list_instances");
    require_exact_names(contract.required, derived_required, "required compatibility");
    require(size_member(compatibility, "required_compatibility_count", "mcp compatibility") == 88U &&
                contract.required.size() == 88U,
            "required compatibility authority must contain 88 unique names");
    const names_t expected_extensions = {
        "analyze_funcs", "calculate", "calculator", "find_insns"
    };
    require_exact_names(contract.extensions, expected_extensions, "AiDA extensions");
    require(set_intersection_of(contract.required, contract.extensions).empty(),
            "AiDA extensions collide with the pinned compatibility surface");
    contract.union_names = set_union_of(contract.required, contract.extensions);
    require(size_member(compatibility, "compatibility_extension_union_count",
                        "mcp compatibility") == 92U &&
                contract.union_names.size() == 92U,
            "compatibility-plus-extension authority must contain 92 unique names");

    const auto& generation = object_member(ledger, "contract_generation", "authority ledger");
    const auto& artifacts = object_member(generation, "artifacts", "contract generation");
    require(artifacts.is_array() && artifacts.size() == 5U,
            "contract generation must declare five canonical artifacts");
    for (const auto& artifact : artifacts) {
        require(artifact.is_string(), "contract generation artifact path must be a string");
        repository_file(root, artifact.get_ref<const std::string&>());
    }
    const auto& reproduction = object_member(
        ledger, "current_surface_reproduction", "authority ledger");
    require(string_member(reproduction, "policy", "surface reproduction") ==
                "byte_exact_current_source_reproduction_and_strict_additive_baseline",
            "surface reproduction policy mismatch");
    return contract;
}

struct descriptor_evidence_t {
    names_t names;
    std::unordered_map<std::string,
        const aida::standalone::mcp::compat::contract_descriptor_t*> by_name;
};

descriptor_evidence_t verify_generated_descriptors(
    const json& contracts_artifact, const json& effects_artifact,
    const json& archive_manifest, const authority_contract_t& authority) {
    using namespace aida::standalone::mcp::compat;
    require(k_pinned_archive_sha256 == k_expected_pinned_archive_sha256,
            "generated descriptor archive fingerprint mismatch");
    require(k_archive_tool_count == 88U && k_compatibility_tool_count == 88U &&
                k_aida_extension_count == 4U && k_union_tool_count == 92U &&
                contract_count() == 88U,
            "generated compatibility arithmetic mismatch");
    require(string_member(object_member(contracts_artifact, "archive", "contracts artifact"),
                          "archive_sha256", "contracts artifact archive") ==
                k_expected_pinned_archive_sha256,
            "contracts artifact archive fingerprint mismatch");
    require(names_from(object_member(contracts_artifact, "compatibility_names", "contracts artifact"),
                       "contracts compatibility names") == authority.required,
            "contracts artifact compatibility inventory mismatch");
    require(names_from(object_member(contracts_artifact, "excluded_tools", "contracts artifact"),
                       "contracts excluded tools") == names_t{"py_eval"},
            "contracts artifact excluded-tool inventory mismatch");
    const auto& contract_rows = object_member(contracts_artifact, "contracts", "contracts artifact");
    const auto& effect_rows = object_member(effects_artifact, "contracts", "effect artifact");
    require(contract_rows.is_array() && contract_rows.size() == 88U &&
                effect_rows.is_array() && effect_rows.size() == 88U,
            "generated descriptor artifacts must each contain 88 contracts");

    std::unordered_map<std::string, const json*> contract_by_name;
    std::unordered_map<std::string, const json*> effect_by_name;
    for (const auto& row : contract_rows) {
        const auto name = string_member(row, "name", "contracts artifact row");
        require(contract_by_name.emplace(name, &row).second,
                "contracts artifact contains duplicate name " + name);
    }
    for (const auto& row : effect_rows) {
        const auto name = string_member(row, "name", "effect artifact row");
        require(effect_by_name.emplace(name, &row).second,
                "effect artifact contains duplicate name " + name);
    }

    descriptor_evidence_t evidence;
    std::size_t archive_backed_count = 0;
    std::size_t proxy_local_count = 0;
    for (std::size_t index = 0; index < contract_count(); ++index) {
        const auto& descriptor = contracts()[index];
        const std::string name(descriptor.name);
        require(!name.empty() && evidence.names.insert(name).second,
                "generated descriptor inventory contains an empty or duplicate name");
        require(evidence.by_name.emplace(name, &descriptor).second,
                "generated descriptor lookup contains duplicate name " + name);
        const auto contract_it = contract_by_name.find(name);
        const auto effect_it = effect_by_name.find(name);
        require(contract_it != contract_by_name.end() && effect_it != effect_by_name.end(),
                "generated descriptor lacks artifact evidence for " + name);
        const auto& contract = *contract_it->second;
        const auto& effect = *effect_it->second;
        require(descriptor.description == string_member(contract, "description", name) &&
                    descriptor.adapter_symbol == string_member(contract, "adapter_symbol", name) &&
                    effect_name(descriptor.effect) == string_member(contract, "effect", name) &&
                    lock_name(descriptor.lock) == string_member(contract, "lock", name) &&
                    descriptor.archive_backed == bool_member(contract, "archive_backed", name) &&
                    descriptor.target_dependent ==
                        bool_member(object_member(contract, "routing", name), "target_dependent", name) &&
                    descriptor.read_only == bool_member(contract, "read_only", name) &&
                    descriptor.unsafe == bool_member(contract, "unsafe", name),
                "generated descriptor scalar fields differ from canonical artifact for " + name);
        require(parse_embedded_json(descriptor.input_schema_json, name + " input schema") ==
                    object_member(contract, "input_schema", name) &&
                    parse_embedded_json(descriptor.output_schema_json, name + " output schema") ==
                    object_member(contract, "output_schema", name) &&
                    parse_embedded_json(descriptor.annotations_json, name + " annotations") ==
                    object_member(contract, "annotations", name),
                "generated descriptor JSON fields differ from canonical artifact for " + name);
        const auto& source = object_member(contract, "source", name);
        require(descriptor.source_path == string_member(source, "path", name) &&
                    descriptor.source_line == size_member(source, "line", name),
                "generated descriptor source provenance differs for " + name);
        const auto& routing_fields = object_member(
            object_member(contract, "routing", name), "fields", name);
        require(routing_fields.is_array(), "routing fields must be an array for " + name);
        names_t selectors;
        for (const auto& field : routing_fields)
            selectors.insert(string_member(field, "name", name + " routing field"));
        require(descriptor.accepts_pid == (selectors.count("pid") != 0U) &&
                    descriptor.accepts_bin_name == (selectors.count("bin_name") != 0U) &&
                    (!descriptor.target_dependent ||
                     (descriptor.accepts_pid && descriptor.accepts_bin_name)),
                "generated descriptor routing selectors differ for " + name);
        require(string_member(effect, "adapter_symbol", name) == descriptor.adapter_symbol &&
                    string_member(effect, "effect", name) == effect_name(descriptor.effect) &&
                    string_member(effect, "lock", name) == lock_name(descriptor.lock) &&
                    bool_member(effect, "archive_backed", name) == descriptor.archive_backed &&
                    bool_member(effect, "target_dependent", name) == descriptor.target_dependent &&
                    bool_member(effect, "read_only", name) == descriptor.read_only &&
                    bool_member(effect, "unsafe", name) == descriptor.unsafe,
                "effect ledger differs from generated descriptor for " + name);
        if (descriptor.archive_backed)
            ++archive_backed_count;
        else {
            ++proxy_local_count;
            require(name == "list_instances", "unexpected non-archive compatibility descriptor " + name);
        }
    }
    require_exact_names(evidence.names, authority.required, "generated descriptors");
    require(archive_backed_count == 87U && proxy_local_count == 1U,
            "generated descriptor archive/proxy arithmetic mismatch");

    require(size_member(archive_manifest, "archive_tool_count", "archive manifest") == 88U &&
                size_member(archive_manifest, "compatibility_tool_count", "archive manifest") == 88U &&
                size_member(archive_manifest, "aida_extension_count", "archive manifest") == 4U &&
                size_member(archive_manifest, "union_tool_count", "archive manifest") == 92U,
            "archive manifest count arithmetic mismatch");
    require(names_from(object_member(archive_manifest, "compatibility_names", "archive manifest"),
                       "archive compatibility names") == authority.required &&
                names_from(object_member(archive_manifest, "aida_extensions", "archive manifest"),
                           "archive extension names") == authority.extensions &&
                names_from(object_member(archive_manifest, "union_names", "archive manifest"),
                           "archive union names") == authority.union_names,
            "archive manifest name inventories mismatch");
    require(string_member(archive_manifest, "contract_ledger_sha256", "archive manifest") ==
                k_generated_contract_ledger_sha256 &&
                string_member(archive_manifest, "effect_ledger_sha256", "archive manifest") ==
                    k_generated_effect_ledger_sha256,
            "archive manifest semantic ledger fingerprints mismatch generated constants");
    return evidence;
}

void verify_legacy_preservation(const json& baseline, const json& current) {
    const auto& baseline_mcp = object_member(baseline, "mcp", "baseline manifest");
    const auto& current_mcp = object_member(current, "mcp", "current manifest");
    const auto& baseline_rows = object_member(baseline_mcp, "registrations", "baseline MCP");
    const auto& current_rows = object_member(current_mcp, "registrations", "current MCP");
    require(baseline_rows.is_array() && baseline_rows.size() == 289U &&
                current_rows.is_array() && current_rows.size() == 331U &&
                size_member(baseline_mcp, "registration_count", "baseline MCP") == 289U &&
                size_member(current_mcp, "registration_count", "current MCP") == 331U,
            "legacy MCP registration count contract mismatch");
    std::unordered_map<std::string, const json*> current_by_name;
    for (const auto& row : current_rows) {
        const auto name = string_member(row, "name", "current MCP registration");
        require(current_by_name.emplace(name, &row).second,
                "current MCP manifest contains duplicate legacy name " + name);
    }
    for (const auto& baseline_row : baseline_rows) {
        const auto name = string_member(baseline_row, "name", "baseline MCP registration");
        const auto found = current_by_name.find(name);
        require(found != current_by_name.end(), "legacy MCP registration was removed: " + name);
        const auto& row = *found->second;
        for (const auto field : {"description", "read_only", "visibility_declared",
                                 "visibility_effective", "workspace_aware"}) {
            if (baseline_row.contains(field))
                require(row.contains(field) && baseline_row.at(field) == row.at(field),
                        "legacy MCP protected field changed for " + name + ": " + field);
        }
        if (baseline_row.contains("parameters"))
            require(row.contains("parameters") &&
                        parameters_preserved(baseline_row.at("parameters"), row.at("parameters")),
                    "legacy MCP parameter contract is not additive for " + name);
        if (baseline_row.contains("input_schema"))
            require(row.contains("input_schema") &&
                        json_preserves(baseline_row.at("input_schema"), row.at("input_schema")),
                    "legacy MCP input schema is not additive for " + name);
    }

    const auto& baseline_resources = object_member(baseline_mcp, "resources", "baseline MCP");
    const auto& current_resources = object_member(current_mcp, "resources", "current MCP");
    require(baseline_resources.is_array() && current_resources.is_array(),
            "MCP resources must be arrays");
    for (const auto& resource : baseline_resources) {
        const auto uri = string_member(resource, "uri", "baseline resource");
        const auto found = std::find_if(current_resources.begin(), current_resources.end(),
            [&](const json& candidate) {
                return candidate.is_object() && candidate.value("uri", std::string()) == uri;
            });
        require(found != current_resources.end(), "legacy MCP resource was removed: " + uri);
        for (const auto field : {"name", "description", "mime_type", "result_fields"})
            require(found->contains(field) && found->at(field) == resource.at(field),
                    "legacy MCP resource field changed for " + uri + ": " + field);
    }
    for (const auto& resource : current_resources) {
        const auto uri = string_member(resource, "uri", "current resource");
        require(uri.rfind("ida://", 0U) != 0U, "legacy ida:// resource was restored: " + uri);
    }

    const auto& baseline_ui = object_member(baseline, "ui", "baseline manifest");
    const auto& current_ui = object_member(current, "ui", "current manifest");
    const auto baseline_views = names_from(object_member(baseline_ui, "center_views", "baseline UI"),
                                           "baseline center views");
    const auto current_views = names_from(object_member(current_ui, "center_views", "current UI"),
                                          "current center views");
    require(std::includes(current_views.begin(), current_views.end(),
                          baseline_views.begin(), baseline_views.end()),
            "one or more baseline center views were removed");
    for (const auto& action : object_member(baseline_ui, "actions", "baseline UI")) {
        const auto label = string_member(action, "label", "baseline UI action");
        const auto& actions = object_member(current_ui, "actions", "current UI");
        require(std::any_of(actions.begin(), actions.end(), [&](const json& candidate) {
                    return candidate.is_object() && candidate.value("label", std::string()) == label;
                }),
                "baseline UI action was removed: " + label);
    }
    for (const auto& shortcut : object_member(baseline_ui, "shortcuts", "baseline UI")) {
        const auto expression = string_member(shortcut, "expression", "baseline shortcut");
        const auto key = string_member(shortcut, "key", "baseline shortcut");
        const auto& shortcuts = object_member(current_ui, "shortcuts", "current UI");
        require(std::any_of(shortcuts.begin(), shortcuts.end(), [&](const json& candidate) {
                    return candidate.is_object() &&
                           candidate.value("expression", std::string()) == expression &&
                           candidate.value("key", std::string()) == key;
                }),
                "baseline shortcut was removed or changed: " + key);
    }

    const auto baseline_methods = names_from(
        object_member(object_member(baseline, "session", "baseline manifest"),
                      "public_method_names", "baseline session"),
        "baseline session methods");
    const auto current_methods = names_from(
        object_member(object_member(current, "session", "current manifest"),
                      "public_method_names", "current session"),
        "current session methods");
    require(std::includes(current_methods.begin(), current_methods.end(),
                          baseline_methods.begin(), baseline_methods.end()),
            "one or more baseline public session methods were removed");

    const auto& baseline_templates = object_member(
        baseline_mcp, "dynamic_registration_templates", "baseline MCP");
    const auto& unresolved_templates = object_member(
        current_mcp, "dynamic_registration_templates", "current MCP");
    const auto& resolved_helpers = object_member(
        current_mcp, "resolved_registration_helpers", "current MCP");
    require(baseline_templates.is_array() && baseline_templates.size() == 2U &&
                unresolved_templates.is_array() && unresolved_templates.empty() &&
                size_member(current_mcp, "unresolved_registration_count", "current MCP") == 0U &&
                resolved_helpers.is_array() && resolved_helpers.size() == 2U &&
                size_member(current_mcp, "resolved_helper_template_count", "current MCP") == 2U &&
                size_member(current_mcp, "resolved_helper_registration_count", "current MCP") == 110U,
            "MCP registration helper resolution must contain two resolved helpers and zero unresolved templates");
    names_t helper_names;
    names_t concrete_names;
    std::size_t concrete_count = 0;
    for (const auto& helper : resolved_helpers) {
        const auto helper_name = string_member(helper, "helper", "resolved registration helper");
        require(helper_names.insert(helper_name).second,
                "resolved registration helper is duplicated: " + helper_name);
        const auto file = string_member(helper, "file", helper_name);
        const auto expression = string_member(helper, "expression", helper_name);
        const auto line = size_member(helper, "line", helper_name);
        require(expression == "alias", "resolved registration helper expression must be alias");
        require(std::any_of(baseline_templates.begin(), baseline_templates.end(),
                    [&](const json& candidate) {
                        return candidate.is_object() &&
                               candidate.value("file", std::string()) == file &&
                               candidate.value("expression", std::string()) == expression &&
                               candidate.value("line", std::size_t{}) == line;
                    }),
                "resolved registration helper lost baseline source provenance: " + helper_name);
        const auto& names = object_member(helper, "concrete_registration_names", helper_name);
        const auto helper_concrete = names_from(names, helper_name + " concrete registrations");
        require(helper_concrete.size() ==
                    size_member(helper, "concrete_registration_count", helper_name),
                "resolved registration helper concrete count mismatch: " + helper_name);
        concrete_count += helper_concrete.size();
        for (const auto& name : helper_concrete) {
            require(current_by_name.count(name) == 1U,
                    "resolved helper names a non-concrete public registration: " + name);
            require(concrete_names.insert(name).second,
                    "concrete public registration is attributed to multiple helpers: " + name);
        }
    }
    require(helper_names == names_t{"register_direct_alias", "register_dispatch_alias"} &&
                concrete_count == 110U && concrete_names.size() == 110U,
            "resolved helper provenance or concrete alias coverage mismatch");
}

void verify_mcp_production_reachability(
    const json& ledger, const json& current,
    const authority_contract_t& authority,
    const json& compatibility_rows,
    const std::filesystem::path& root) {
    const auto& current_contract = object_member(
        object_member(ledger, "current_surface_contract", "authority ledger"),
        "mcp", "current surface contract");
    const auto& reachability_authority = object_member(
        current_contract, "production_reachability", "current surface MCP");
    require(reachability_authority.is_object() && reachability_authority.size() == 17U,
            "MCP production reachability authority field inventory is invalid");
    const auto& current_mcp = object_member(current, "mcp", "current manifest");
    const auto& policy = object_member(
        current_mcp, "production_reachability", "current MCP");
    require(policy.is_object() && policy.size() == 13U &&
                size_member(policy, "schema_version", "MCP production reachability") == 1U,
            "MCP production reachability schema is invalid");

    const auto& registrations = object_member(current_mcp, "registrations", "current MCP");
    require(registrations.is_array() && registrations.size() == 331U,
            "MCP production reachability requires 331 concrete registrations");
    const auto sources = load_cpp_reachability_sources(root);
    names_t terminal_offsets;
    for (const auto& row : registrations) {
        const auto name = string_member(row, "name", "MCP reachability registration");
        const auto& source = object_member(row, "source", name);
        const auto offset = signed_member(source, "character_offset", name + " source");
        if (offset >= 0) {
            const auto file = string_member(source, "file", name + " source");
            const auto unit_it = sources.sources.find(file);
            require(unit_it != sources.sources.end(),
                    "MCP registration source is outside the registrar source inventory: " +
                        name);
            terminal_offsets.insert(
                file + ":" + std::to_string(utf8_byte_offset(
                    unit_it->second.source, static_cast<std::size_t>(offset))));
        }
    }

    std::vector<const cpp_registrar_t*> roots;
    for (const auto& definition : sources.definitions) {
        if (definition.symbol == "mcp_standalone::register_standalone_tools")
            roots.push_back(&definition);
    }
    require(roots.size() == 1U,
            "production MCP root registrar definition count is not exactly one");
    const auto route_entry = unique_owned_code_call(
        sources, "src/standalone/src/core/mcp/mcp_standalone_tools.cpp",
        std::regex(R"(\bregister_c03_compatibility_tools\s*\(\s*srv\s*\))"),
        "C03 compatibility root registrar edge", *roots.front());
    auto direct_terminal_offsets = terminal_offsets;
    const auto route_entry_file = string_member(
        route_entry, "file", "C03 compatibility root registrar edge");
    const auto route_entry_unit = sources.sources.find(route_entry_file);
    require(route_entry_unit != sources.sources.end(),
            "C03 compatibility root registrar source is unavailable");
    direct_terminal_offsets.insert(
        route_entry_file + ":" + std::to_string(utf8_byte_offset(
            route_entry_unit->second.source,
            size_member(route_entry, "character_offset",
                        "C03 compatibility root registrar edge"))));
    const auto derived = derive_reachability(
        sources, direct_terminal_offsets);
    require(object_member(policy, "production_entry", "MCP production reachability") ==
                derived.production_entry,
            "MCP production entry differs from independently derived code evidence");
    require(object_member(policy, "registrars", "MCP production reachability") ==
                derived.registrars &&
                object_member(policy, "edges", "MCP production reachability") == derived.edges,
            "MCP registrar graph differs from independently derived code reachability");

    std::vector<std::string> graph_lines;
    for (const auto& registrar : derived.registrars) {
        const auto& parent = object_member(registrar, "parent_id", "derived registrar");
        const auto parent_id = parent.is_null() ? std::string() : parent.get<std::string>();
        graph_lines.push_back(
            "R\t" + string_member(registrar, "id", "derived registrar") + "\t" +
            string_member(registrar, "symbol", "derived registrar") + "\t" +
            string_member(registrar, "file", "derived registrar") + "\t" +
            std::to_string(size_member(registrar, "line", "derived registrar")) + "\t" +
            parent_id);
    }
    for (const auto& edge : derived.edges) {
        graph_lines.push_back(
            "E\t" + string_member(edge, "caller_id", "derived edge") + "\t" +
            string_member(edge, "callee_id", "derived edge") + "\t" +
            string_member(edge, "file", "derived edge") + "\t" +
            std::to_string(size_member(edge, "line", "derived edge")) + "\t" +
            std::to_string(size_member(edge, "character_offset", "derived edge")) + "\t" +
            string_member(edge, "expression", "derived edge"));
    }
    const auto graph_hash = sha256_sorted_unique_lines(graph_lines);
    require(size_member(policy, "reachable_registrar_count", "MCP production reachability") ==
                derived.registrars.size() &&
                size_member(policy, "registrar_edge_count", "MCP production reachability") ==
                    derived.edges.size() &&
                string_member(policy, "registrar_graph_sha256",
                              "MCP production reachability") == graph_hash,
            "MCP registrar graph cardinality or fingerprint is invalid");

    const auto root_id = string_member(
        derived.production_entry, "root_registrar_id", "derived production entry");
    const auto root_definition = derived.definitions_by_id.find(root_id);
    require(root_definition != derived.definitions_by_id.end(),
            "derived production root definition is unavailable");
    const auto generated = derive_generated_route(
        sources, *root_definition->second, compatibility_rows,
        derived.edges, terminal_offsets);
    require(object_member(policy, "generated_route", "MCP production reachability") ==
                generated.route,
            "generated MCP route differs from independently derived enclosing definitions");

    names_t reachable_ids;
    for (const auto& registrar : derived.registrars) {
        require(reachable_ids.insert(
                    string_member(registrar, "id", "derived registrar")).second,
                "derived registrar identity is duplicated");
    }
    std::vector<std::string> row_lines;
    names_t registration_names;
    names_t projected_names;
    std::size_t direct_count = 0;
    std::size_t projection_count = 0;
    for (const auto& row : registrations) {
        const auto name = string_member(row, "name", "MCP reachability registration");
        require(registration_names.insert(name).second,
                "MCP reachability registration name is duplicated: " + name);
        const auto& source = object_member(row, "source", name);
        const auto file = string_member(source, "file", name + " source");
        const auto line = size_member(source, "line", name + " source");
        const auto offset = signed_member(source, "character_offset", name + " source");
        const auto& binding = object_member(
            row, "production_reachability", name + " registration");
        if (offset >= 0) {
            const auto unit_it = sources.sources.find(file);
            require(unit_it != sources.sources.end(),
                    "MCP registration source is outside the registrar graph: " + name);
            const auto& unit = unit_it->second;
            const auto absolute = utf8_byte_offset(
                unit.source, static_cast<std::size_t>(offset));
            require(absolute < unit.mask.size() && source_line(unit.source, absolute) == line,
                    "MCP registration source offset or line is invalid: " + name);
            const std::array<std::string_view, 4> syntaxes = {
                ".register_tool", "register_tool",
                "register_direct_alias", "register_dispatch_alias"
            };
            require(std::any_of(syntaxes.begin(), syntaxes.end(), [&](auto syntax) {
                        if (unit.mask.compare(absolute, syntax.size(), syntax) != 0)
                            return false;
                        auto cursor = absolute + syntax.size();
                        while (cursor < unit.mask.size() &&
                               std::isspace(static_cast<unsigned char>(
                                   unit.mask[cursor])) != 0) {
                            ++cursor;
                        }
                        return cursor < unit.mask.size() && unit.mask[cursor] == '(';
                    }),
                    "MCP registration offset is not code registration syntax: " + name);
            const auto opening = unit.mask.find('(', absolute);
            require(opening != std::string::npos,
                    "MCP registration call opening delimiter is unavailable: " + name);
            const auto closing = matching_index(unit.mask, opening, '(', ')');
            const auto evidence = string_member(source, "evidence", name + " source");
            if (evidence != "assigned_tool_definition") {
                const auto call = std::string_view(unit.source).substr(
                    absolute, closing - absolute + 1U);
                require(call.find("\"" + name + "\"") != std::string_view::npos,
                        "MCP registration call lacks its concrete name: " + name);
            }
            std::vector<const cpp_registrar_t*> owners;
            for (const auto& definition : sources.definitions) {
                if (definition.file == file && definition.body_start < absolute &&
                    absolute < definition.body_end) {
                    owners.push_back(&definition);
                }
            }
            require(owners.size() == 1U,
                    "MCP registration does not have exactly one enclosing registrar: " + name);
            const auto* registrar = owners.front();
            require(reachable_ids.count(registrar->id) == 1U &&
                        derived.chains.count(registrar->id) == 1U,
                    "MCP registration is in an unreachable registrar: " + name);
            const auto& chain = derived.chains.at(registrar->id);
            const json expected = {
                {"mode", "direct_registration"},
                {"registrar_id", registrar->id},
                {"registrar_symbol", registrar->symbol},
                {"chain", chain},
                {"chain_sha256", sha256_lines(chain)}
            };
            require(binding == expected,
                    "MCP direct registration has an invalid registrar binding: " + name);
            ++direct_count;
        } else {
            require(offset == -1,
                    "MCP generated projection uses an invalid negative source offset: " + name);
            const auto generated_it = generated.bindings_by_name.find(name);
            require(generated_it != generated.bindings_by_name.end(),
                    "MCP generated projection lacks a per-name route: " + name);
            const auto& generated_binding = generated_it->second;
            const json expected = {
                {"mode", "generated_compatibility_projection"},
                {"generated_branch", string_member(
                    generated_binding, "branch", name + " generated binding")},
                {"registrar_id", string_member(
                    generated_binding, "registrar_id", name + " generated binding")},
                {"registrar_symbol", string_member(
                    generated_binding, "registrar_symbol", name + " generated binding")},
                {"chain", object_member(
                    generated_binding, "chain", name + " generated binding")},
                {"chain_sha256", string_member(
                    generated_binding, "chain_sha256", name + " generated binding")}
            };
            require(binding == expected,
                    "MCP generated projection has an invalid per-name route: " + name);
            projected_names.insert(name);
            ++projection_count;
        }
        row_lines.push_back(
            name + "\t" + string_member(binding, "mode", name + " binding") + "\t" +
            string_member(binding, "registrar_id", name + " binding") + "\t" +
            string_member(binding, "chain_sha256", name + " binding"));
    }
    std::sort(row_lines.begin(), row_lines.end());
    const auto row_hash = sha256_lines(row_lines);
    require(direct_count + projection_count == 331U &&
                direct_count == 281U && projection_count == 50U &&
                size_member(policy, "concrete_registration_count",
                            "MCP production reachability") == 331U &&
                size_member(policy, "direct_registration_count",
                            "MCP production reachability") == direct_count &&
                size_member(policy, "generated_projection_count",
                            "MCP production reachability") == projection_count &&
                string_member(policy, "row_binding_sha256",
                              "MCP production reachability") == row_hash,
            "MCP registration reachability cardinality or fingerprint is invalid");
    require_exact_names(
        projected_names,
        names_from(object_member(current_mcp, "generated_only_names", "current MCP"),
                   "current generated-only registrations"),
        "MCP generated-only production projection");

    names_t generated_names;
    for (const auto& row : compatibility_rows) {
        const auto name = string_member(row, "name", "canonical generated registration");
        require(generated_names.insert(name).second,
                "canonical generated registration is duplicated: " + name);
        const auto binding_it = generated.bindings_by_name.find(name);
        require(binding_it != generated.bindings_by_name.end() &&
                    object_member(row, "production_reachability",
                                  name + " canonical registration") == binding_it->second,
                "canonical generated registration lacks exact per-name reachability: " + name);
    }
    require_exact_names(generated_names, authority.union_names,
                        "canonical generated production reachability");

    const auto generated_route_hash = string_member(
        generated.route, "route_sha256", "derived generated route");
    const auto generated_binding_hash = string_member(
        generated.route, "binding_sha256", "derived generated route");
    const std::map<std::string, json> expected_authority = {
        {"schema_version", 1},
        {"concrete_registration_count", 331},
        {"direct_registration_count", direct_count},
        {"generated_projection_count", projection_count},
        {"reachable_registrar_count", derived.registrars.size()},
        {"registrar_edge_count", derived.edges.size()},
        {"row_binding_sha256", row_hash},
        {"registrar_graph_sha256", graph_hash},
        {"generated_route_node_count", 7},
        {"generated_route_edge_count", 7},
        {"generated_terminal_operation_count", 2},
        {"generated_binding_count", 92},
        {"generated_compatibility_count", 88},
        {"generated_extension_count", 4},
        {"generated_route_sha256", generated_route_hash},
        {"generated_binding_sha256", generated_binding_hash}
    };
    for (const auto& [field, expected] : expected_authority) {
        require(reachability_authority.contains(field) &&
                    reachability_authority.at(field) == expected,
                "MCP production reachability differs from authority at " + field);
    }
    const auto& entry_authority = object_member(
        reachability_authority, "production_entry", "reachability authority");
    const json expected_entry_authority = {
        {"file", string_member(derived.production_entry, "file", "derived entry")},
        {"expression", string_member(
            derived.production_entry, "expression", "derived entry")},
        {"root_registrar_symbol", string_member(
            derived.production_entry, "root_registrar_symbol", "derived entry")}
    };
    require(entry_authority == expected_entry_authority,
            "MCP production entry authority is invalid");

    const auto source_files = names_from(
        object_member(policy, "source_files", "MCP production reachability"),
        "MCP production reachability source files");
    names_t expected_source_files;
    for (const auto& registrar : derived.registrars)
        expected_source_files.insert(string_member(registrar, "file", "derived registrar"));
    expected_source_files.insert("src/standalone/src/core/ai/standalone_chat.cpp");
    expected_source_files.insert("src/standalone/src/core/mcp/mcp_standalone.cpp");
    expected_source_files.insert(
        "src/standalone/src/core/mcp/compat/c03_compatibility_registration.cpp");
    expected_source_files.insert(
        "src/standalone/src/core/mcp/compat/mcp_server_integration.cpp");
    require_exact_names(source_files, expected_source_files,
                        "MCP production reachability source files");

    std::unordered_map<std::string, std::string> evidence_hashes;
    const auto& evidence = object_member(current, "evidence_source_hashes", "current manifest");
    require(evidence.is_array(), "current source hash evidence must be an array");
    for (const auto& row : evidence) {
        const auto file = string_member(row, "file", "source hash evidence");
        const auto hash = string_member(row, "sha256", "source hash evidence");
        require(evidence_hashes.emplace(file, hash).second,
                "source hash evidence contains a duplicate file: " + file);
    }
    for (const auto& file : source_files) {
        const auto found = evidence_hashes.find(file);
        require(found != evidence_hashes.end() &&
                    found->second == sha256_text(read_bounded(
                        repository_file(root, file), k_maximum_source_bytes)),
                "MCP reachability source hash is missing or stale: " + file);
    }
}

void verify_runtime_and_final_contract(
    const json& ledger, const json& current, const authority_contract_t& authority,
    const descriptor_evidence_t& descriptors, const std::filesystem::path& root) {
    const auto& current_contract = object_member(
        object_member(ledger, "current_surface_contract", "authority ledger"),
        "mcp", "current surface contract");
    const auto& current_mcp = object_member(current, "mcp", "current manifest");
    require(size_member(current_mcp, "registration_count", "current MCP") == 331U &&
                size_member(current_mcp, "unique_name_count", "current MCP") == 331U &&
                size_member(current_mcp, "generated_registration_count", "current MCP") == 92U &&
                size_member(current_mcp, "generated_overlap_count", "current MCP") == 42U &&
                size_member(current_mcp, "generated_only_count", "current MCP") == 50U &&
                size_member(current_mcp, "effective_registration_count", "current MCP") == 381U,
            "current MCP legacy/generated/effective arithmetic mismatch");
    require(size_member(current_contract, "legacy_resolved_count", "current surface MCP") == 331U &&
                size_member(current_contract, "generated_registration_count", "current surface MCP") == 92U &&
                size_member(current_contract, "generated_overlap_count", "current surface MCP") == 42U &&
                size_member(current_contract, "generated_only_count", "current surface MCP") == 50U &&
                size_member(current_contract, "effective_registration_count", "current surface MCP") == 381U &&
                size_member(current_contract, "unresolved_registration_count", "current surface MCP") == 0U &&
                size_member(current_contract, "resolved_helper_template_count", "current surface MCP") == 2U &&
                size_member(current_contract, "resolved_helper_registration_count", "current surface MCP") == 110U,
            "authority ledger current MCP arithmetic mismatch");
    const auto& helper_authority = object_member(
        current_contract, "resolved_helpers", "current surface MCP");
    require(helper_authority.is_object() && helper_authority.size() == 2U &&
                size_member(helper_authority, "register_direct_alias", "resolved helper authority") == 101U &&
                size_member(helper_authority, "register_dispatch_alias", "resolved helper authority") == 9U,
            "authority ledger resolved-helper cardinality mismatch");

    const auto legacy_names = [&] {
        names_t result;
        for (const auto& row : object_member(current_mcp, "registrations", "current MCP")) {
            const auto name = string_member(row, "name", "current MCP registration");
            require(result.insert(name).second, "current MCP contains duplicate legacy registration " + name);
        }
        return result;
    }();
    const auto generated_names = names_from(
        object_member(current_mcp, "generated_union_names", "current MCP"),
        "generated union names");
    const auto overlap_names = names_from(
        object_member(current_mcp, "generated_overlap_names", "current MCP"),
        "generated overlap names");
    const auto generated_only_names = names_from(
        object_member(current_mcp, "generated_only_names", "current MCP"),
        "generated-only names");
    const auto effective_names = names_from(
        object_member(current_mcp, "effective_registration_names", "current MCP"),
        "effective registration names");
    require_exact_names(generated_names, authority.union_names, "current generated union");
    require_exact_names(overlap_names, set_intersection_of(legacy_names, authority.union_names),
                        "current generated overlap");
    require_exact_names(generated_only_names, set_difference_of(authority.union_names, legacy_names),
                        "current generated-only inventory");
    require_exact_names(effective_names, set_union_of(legacy_names, authority.union_names),
                        "current effective MCP inventory");
    require(!effective_names.count("py_eval"), "py_eval is present in the effective MCP surface");

    const auto& compatibility = object_member(
        object_member(current, "source_contracts", "current manifest"),
        "ida_compatibility", "current source contracts");
    require(size_member(compatibility, "registration_count", "IDA compatibility") == 92U &&
                size_member(compatibility, "archive_backed_count", "IDA compatibility") == 87U &&
                size_member(compatibility, "proxy_local_count", "IDA compatibility") == 1U &&
                size_member(compatibility, "extension_count", "IDA compatibility") == 4U,
            "current canonical compatibility arithmetic mismatch");
    require_exact_names(names_from(object_member(compatibility, "union_names", "IDA compatibility"),
                                   "IDA compatibility union"),
                        authority.union_names, "current canonical compatibility union");

    const auto& artifact_authority = object_member(
        object_member(ledger, "contract_generation", "authority ledger"),
        "descriptor_artifact_sha256", "contract generation");
    const auto& descriptor_artifacts = object_member(
        compatibility, "descriptor_artifacts", "IDA compatibility");
    const std::array<std::pair<std::string_view, std::string_view>, 3> artifact_fields = {{
        {"contracts", "src/standalone/src/resources/mcp/ida_pro_mcp_2_0_0/contracts.json"},
        {"effects", "src/standalone/src/resources/mcp/ida_pro_mcp_2_0_0/effect_ledger.json"},
        {"archive_manifest", "src/standalone/src/resources/mcp/ida_pro_mcp_2_0_0/archive_manifest.json"}
    }};
    for (const auto& [field, expected_path] : artifact_fields) {
        const auto& artifact = object_member(descriptor_artifacts, field, "descriptor artifacts");
        const auto path = string_member(artifact, "path", std::string(field));
        const auto hash = string_member(artifact, "sha256", std::string(field));
        require(path == expected_path && artifact_authority.contains(path) &&
                    artifact_authority.at(path).is_string() &&
                    artifact_authority.at(path).get<std::string>() == hash && hash.size() == 64U,
                "descriptor artifact path or byte fingerprint mismatch for " + std::string(field));
        repository_file(root, path);
    }

    const auto& legacy_projection = object_member(
        compatibility, "legacy_schema_projection", "IDA compatibility");
    require(size_member(legacy_projection, "registration_count", "legacy schema projection") == 42U,
            "legacy IDA schema projection must preserve 42 registrations");

    const std::array<std::string_view, 14> required_row_keys = {
        "name", "descriptor_source", "adapter_symbol", "effect", "lock",
        "target_dependent", "accepts_pid", "accepts_bin_name", "read_only", "unsafe",
        "production_handler", "functional_fixture", "domain", "production_reachability"
    };
    names_t expected_row_keys;
    for (const auto key : required_row_keys)
        expected_row_keys.emplace(key);
    const auto& rows = object_member(compatibility, "registrations", "IDA compatibility");
    require(rows.is_array() && rows.size() == 92U,
            "canonical compatibility registration table must contain 92 rows");
    std::unordered_map<std::string, const json*> rows_by_name;
    for (const auto& row : rows) {
        names_t keys;
        for (auto it = row.begin(); it != row.end(); ++it)
            keys.insert(it.key());
        require_exact_names(keys, expected_row_keys, "canonical compatibility row keys");
        const auto name = string_member(row, "name", "canonical compatibility row");
        require(rows_by_name.emplace(name, &row).second,
                "canonical compatibility table contains duplicate name " + name);
        for (const auto field : {"descriptor_source", "adapter_symbol", "effect", "lock",
                                 "production_handler", "functional_fixture", "domain"})
            string_member(row, field, name);
        for (const auto field : {"target_dependent", "accepts_pid", "accepts_bin_name",
                                 "read_only", "unsafe"})
            bool_member(row, field, name);
        if (const auto found = descriptors.by_name.find(name); found != descriptors.by_name.end()) {
            const auto& descriptor = *found->second;
            require(string_member(row, "descriptor_source", name) == descriptor.source_path &&
                        string_member(row, "adapter_symbol", name) == descriptor.adapter_symbol &&
                        string_member(row, "effect", name) == effect_name(descriptor.effect) &&
                        string_member(row, "lock", name) == lock_name(descriptor.lock) &&
                        bool_member(row, "target_dependent", name) == descriptor.target_dependent &&
                        bool_member(row, "accepts_pid", name) == descriptor.accepts_pid &&
                        bool_member(row, "accepts_bin_name", name) == descriptor.accepts_bin_name &&
                        bool_member(row, "read_only", name) == descriptor.read_only &&
                        bool_member(row, "unsafe", name) == descriptor.unsafe,
                    "canonical compatibility row differs from generated descriptor for " + name);
        } else {
            require(authority.extensions.count(name) == 1U,
                    "canonical compatibility row has no generated descriptor or extension authority: " + name);
        }
    }
    require_exact_names([&] {
        names_t result;
        for (const auto& [name, _] : rows_by_name)
            result.insert(name);
        return result;
    }(), authority.union_names, "canonical compatibility rows");
    verify_mcp_production_reachability(
        ledger, current, authority, rows, root);

    const auto& ledger_domains = object_member(current_contract, "domains", "current surface MCP");
    const auto& final_domains = object_member(compatibility, "domains", "IDA compatibility");
    require(ledger_domains.is_object() && ledger_domains.size() == 12U &&
                final_domains.is_array() && final_domains.size() == 12U,
            "compatibility domain inventory must contain 12 domains");
    names_t domain_names;
    names_t domain_union;
    std::unordered_map<std::string, std::string> source_cache;
    for (const auto& domain : final_domains) {
        const auto domain_name = string_member(domain, "domain", "compatibility domain");
        require(domain_names.insert(domain_name).second,
                "compatibility domain is duplicated: " + domain_name);
        const auto ledger_domain_it = ledger_domains.find(domain_name);
        require(ledger_domain_it != ledger_domains.end(),
                "compatibility domain lacks authority ledger entry: " + domain_name);
        const auto names = names_from(object_member(domain, "names", domain_name),
                                      domain_name + " names");
        const auto ledger_names = names_from(object_member(*ledger_domain_it, "names", domain_name),
                                             domain_name + " authority names");
        require_exact_names(names, ledger_names, domain_name + " domain");
        for (const auto& name : names) {
            require(domain_union.insert(name).second,
                    "compatibility name is assigned to multiple domains: " + name);
            const auto row_it = rows_by_name.find(name);
            require(row_it != rows_by_name.end() &&
                        string_member(*row_it->second, "domain", name) == domain_name,
                    "compatibility row domain assignment mismatch for " + name);
        }
        const auto handler = string_member(domain, "production_handler", domain_name);
        const auto fixture = string_member(domain, "functional_fixture", domain_name);
        const auto handler_marker = string_member(domain, "handler_marker", domain_name);
        const auto fixture_marker = string_member(domain, "fixture_marker", domain_name);
        require(handler == string_member(*ledger_domain_it, "handler", domain_name) &&
                    fixture == string_member(*ledger_domain_it, "fixture", domain_name) &&
                    handler_marker == string_member(*ledger_domain_it, "handler_marker", domain_name) &&
                    fixture_marker == string_member(*ledger_domain_it, "fixture_marker", domain_name),
                "compatibility domain source evidence differs from authority for " + domain_name);
        auto load_source = [&](const std::string& relative) -> const std::string& {
            auto [it, inserted] = source_cache.try_emplace(relative);
            if (inserted)
                it->second = read_bounded(repository_file(root, relative), k_maximum_source_bytes);
            return it->second;
        };
        const auto& handler_source = load_source(handler);
        const auto& fixture_source = load_source(fixture);
        require(handler_source.find(handler_marker) != std::string::npos,
                "production handler marker is absent for domain " + domain_name);
        require(fixture_source.find(fixture_marker) != std::string::npos,
                "functional fixture marker is absent for domain " + domain_name);
        for (const auto& name : names) {
            const auto row_it = rows_by_name.find(name);
            require(string_member(*row_it->second, "production_handler", name) == handler &&
                        string_member(*row_it->second, "functional_fixture", name) == fixture,
                    "compatibility row source binding mismatch for " + name);
            require(fixture_source.find("\"" + name + "\"") != std::string::npos,
                    "functional fixture lacks explicit tool coverage for " + name);
        }
    }
    require_exact_names(domain_union, authority.union_names, "compatibility domain partition");

    mcp_standalone::tool_registry_t registry;
    mcp_standalone::register_c03_compatibility_tools(registry);
    const auto runtime_tools = registry.snapshot_tools();
    require(runtime_tools.size() == 92U,
            "production compatibility registry must contain exactly 92 tools");
    names_t runtime_names;
    for (const auto& tool : runtime_tools) {
        require(runtime_names.insert(tool.name).second,
                "production compatibility registry contains duplicate name " + tool.name);
        const auto row_it = rows_by_name.find(tool.name);
        require(row_it != rows_by_name.end(),
                "production compatibility registry contains an undeclared tool " + tool.name);
        const auto& row = *row_it->second;
        const auto target_dependent = bool_member(row, "target_dependent", tool.name);
        require(tool.visibility == mcp_standalone::tool_visibility_t::external_visible &&
                    tool.production_registry_dispatch &&
                    tool.read_only == bool_member(row, "read_only", tool.name) &&
                    tool.target_independent == !target_dependent &&
                    tool.input_schema.is_object() && tool.output_schema.is_object() &&
                    tool.annotations.is_object() && !tool.description.empty(),
                "production compatibility registry metadata mismatch for " + tool.name);
        require(target_dependent ? static_cast<bool>(tool.workspace_handler) :
                                   static_cast<bool>(tool.handler),
                "production compatibility registry lacks a real dispatch handler for " + tool.name);
        if (const auto found = descriptors.by_name.find(tool.name); found != descriptors.by_name.end()) {
            const auto& descriptor = *found->second;
            require(tool.description == descriptor.description &&
                        tool.input_schema == parse_embedded_json(
                            descriptor.input_schema_json, tool.name + " runtime input") &&
                        tool.output_schema == parse_embedded_json(
                            descriptor.output_schema_json, tool.name + " runtime output") &&
                        tool.annotations == parse_embedded_json(
                            descriptor.annotations_json, tool.name + " runtime annotations"),
                    "production registry schema or description differs for " + tool.name);
        }
    }
    require_exact_names(runtime_names, authority.union_names, "production compatibility registry");

    const auto registration_source = string_member(
        compatibility, "registration_source", "IDA compatibility");
    const auto server_source = string_member(
        compatibility, "server_integration_source", "IDA compatibility");
    require(registration_source == string_member(current_contract, "registration_source",
                                                  "current surface MCP") &&
                server_source == string_member(current_contract, "server_integration_source",
                                               "current surface MCP"),
            "canonical compatibility integration paths differ from authority");
    const auto production_entry = string_member(current_contract, "production_entry_source",
                                                 "current surface MCP");
    const auto registration_text = read_bounded(repository_file(root, registration_source),
                                                k_maximum_source_bytes);
    const auto server_text = read_bounded(repository_file(root, server_source),
                                          k_maximum_source_bytes);
    const auto entry_text = read_bounded(repository_file(root, production_entry),
                                         k_maximum_source_bytes);
    const auto& markers = object_member(current_contract, "production_entry_markers",
                                        "current surface MCP");
    require(markers.is_array() && !markers.empty(),
            "production compatibility integration marker inventory is empty");
    const auto joined = registration_text + server_text + entry_text;
    for (const auto& marker : markers) {
        require(marker.is_string() && !marker.get_ref<const std::string&>().empty() &&
                    joined.find(marker.get_ref<const std::string&>()) != std::string::npos,
                "production compatibility integration marker is absent");
    }
}

void verify_public_surfaces(const json& ledger, const json& current,
                            const std::filesystem::path& root) {
    const auto& authority = object_member(ledger, "current_surface_contract", "authority ledger");
    const auto& preservation = object_member(ledger, "preservation_baseline", "authority ledger");
    const auto& surfaces = object_member(current, "public_surfaces", "current manifest");
    const auto& commands = object_member(surfaces, "commands", "public surfaces");
    const auto& command_authority = object_member(authority, "commands", "current surface contract");
    require(size_member(commands, "builtin_count", "public commands") ==
                size_member(command_authority, "builtin_count", "command authority"),
            "public built-in command count mismatch");
    const auto command_names = names_from(object_member(commands, "builtin_names", "public commands"),
                                          "public built-in commands");
    require(command_names.size() == 34U, "public built-in command inventory must contain 34 names");
    require_exact_names(command_names,
        names_from(object_member(object_member(preservation, "commands", "preservation baseline"),
                                 "builtin_names", "preserved commands"),
                   "preserved built-in commands"),
        "preserved built-in commands");
    require_exact_names(
        names_from(object_member(commands, "dynamic_producers", "public commands"),
                   "public dynamic command producers"),
        names_from(object_member(command_authority, "dynamic_producers", "command authority"),
                   "authority dynamic command producers"),
        "dynamic command producers");

    const auto& test_lab = object_member(surfaces, "test_lab", "public surfaces");
    const auto& test_lab_authority = object_member(authority, "test_lab", "current surface contract");
    const auto feature_count = size_member(test_lab, "feature_count", "public Test Lab");
    require(feature_count >= size_member(test_lab_authority, "minimum_feature_count",
                                         "Test Lab authority"),
            "public Test Lab feature count regressed below the baseline");
    const auto& features = object_member(test_lab, "features", "public Test Lab");
    require(features.is_array(), "public Test Lab features must be an array");
    names_t feature_ids;
    for (const auto& feature : features) {
        const auto category = string_member(feature, "category", "public Test Lab feature");
        const auto name = string_member(feature, "name", "public Test Lab feature");
        require(feature_ids.insert(category + ":" + name).second,
                "public Test Lab feature is duplicated: " + category + ":" + name);
        const auto& source = object_member(feature, "source", "public Test Lab feature");
        repository_file(root, string_member(source, "file", "public Test Lab feature source"));
        require(size_member(source, "line", "public Test Lab feature source") != 0U,
                "public Test Lab feature source line must be nonzero");
    }
    require(feature_ids.size() == feature_count,
            "public Test Lab feature count differs from its unique inventory");
    const auto required_features = names_from(
        object_member(test_lab_authority, "required_additive_features", "Test Lab authority"),
        "required additive Test Lab features");
    require(std::includes(feature_ids.begin(), feature_ids.end(),
                          required_features.begin(), required_features.end()),
            "required additive Test Lab feature is absent");
    const auto preserved_features = names_from(
        object_member(object_member(preservation, "test_lab", "preservation baseline"),
                      "feature_ids", "preserved Test Lab"),
        "preserved Test Lab features");
    require(std::includes(feature_ids.begin(), feature_ids.end(),
                          preserved_features.begin(), preserved_features.end()),
            "one or more preserved Test Lab features were removed");

    const auto& workbench = object_member(surfaces, "workbench", "public surfaces");
    const auto& workbench_authority = object_member(authority, "workbench", "current surface contract");
    require_exact_names(
        names_from(object_member(workbench, "analysis_document_kinds", "public workbench"),
                   "public workbench document kinds"),
        names_from(object_member(workbench_authority, "analysis_document_kinds",
                                 "workbench authority"),
                   "authority workbench document kinds"),
        "workbench analysis document kinds");
    require(string_member(workbench, "default_analysis_document", "public workbench") ==
                string_member(workbench_authority, "default_analysis_document",
                              "workbench authority") &&
                bool_member(workbench, "per_workspace_persistence", "public workbench") &&
                bool_member(workbench_authority, "per_workspace_persistence",
                            "workbench authority"),
            "workbench default or persistence contract mismatch");

    const auto& overlay = object_member(surfaces, "overlay", "public surfaces");
    const auto& overlay_authority = object_member(authority, "overlay", "current surface contract");
    for (const auto field : {"legacy_ordinal_min", "legacy_ordinal_max",
                             "appended_ordinal_min", "appended_ordinal_max"})
        require(size_member(overlay, field, "public overlay") ==
                    size_member(overlay_authority, field, "overlay authority"),
                "overlay ordinal contract mismatch at " + std::string(field));
    require(size_member(overlay, "legacy_ordinal_min", "public overlay") == 0U &&
                size_member(overlay, "legacy_ordinal_max", "public overlay") == 13U &&
                size_member(overlay, "appended_ordinal_min", "public overlay") == 14U &&
                size_member(overlay, "appended_ordinal_max", "public overlay") == 17U,
            "overlay ordinal ranges are not append-only 0-17");
    const auto& operations = object_member(overlay, "operations", "public overlay");
    const auto authority_operations = names_from(
        object_member(overlay_authority, "operations", "overlay authority"),
        "authority overlay operations");
    require(operations.is_array() && operations.size() == 18U &&
                size_member(overlay, "operation_count", "public overlay") == 18U,
            "public overlay operation table must contain 18 rows");
    names_t operation_names;
    for (std::size_t index = 0; index < operations.size(); ++index) {
        const auto& operation = operations.at(index);
        const auto name = string_member(operation, "name", "public overlay operation");
        require(size_member(operation, "ordinal", "public overlay operation") == index &&
                    operation_names.insert(name).second,
                "public overlay operation ordinals must be unique and contiguous");
    }
    require_exact_names(operation_names, authority_operations, "overlay operations");

    const auto& dead_paths = object_member(surfaces, "dead_paths", "public surfaces");
    const auto& dead_authority = object_member(authority, "dead_paths", "current surface contract");
    const auto absent = names_from(object_member(dead_paths, "absent_paths", "public dead paths"),
                                   "public absent paths");
    const auto replacements = names_from(
        object_member(dead_paths, "replacement_paths", "public dead paths"),
        "public replacement paths");
    require_exact_names(absent,
        names_from(object_member(dead_authority, "absent", "dead-path authority"),
                   "authority absent paths"), "dead paths");
    require_exact_names(replacements,
        names_from(object_member(dead_authority, "replacements", "dead-path authority"),
                   "authority replacement paths"), "replacement paths");
    for (const auto& relative : absent) {
        std::error_code ec;
        require(!std::filesystem::exists(root / std::filesystem::u8path(relative), ec),
                "replaced dead path still exists: " + relative);
    }
    for (const auto& relative : replacements)
        repository_file(root, relative);

    std::unordered_map<std::string, std::string> evidence_hashes;
    const auto& evidence = object_member(current, "evidence_source_hashes", "current manifest");
    require(evidence.is_array(), "current source hash evidence must be an array");
    for (const auto& row : evidence) {
        const auto file = string_member(row, "file", "source hash evidence");
        const auto hash = string_member(row, "sha256", "source hash evidence");
        require(hash.size() == 64U &&
                    std::all_of(hash.begin(), hash.end(), [](unsigned char ch) {
                        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
                               (ch >= 'A' && ch <= 'F');
                    }) && evidence_hashes.emplace(file, hash).second,
                "source hash evidence is malformed or duplicated: " + file);
    }

    const auto& authority_responsibilities = object_member(
        dead_authority, "responsibilities", "dead-path authority");
    const auto& retirements = object_member(dead_paths, "retirements", "public dead paths");
    require(authority_responsibilities.is_object() && authority_responsibilities.size() == 2U &&
                retirements.is_array() && retirements.size() == 2U,
            "dead-path retirement graph must contain two explicit responsibilities");
    names_t retired_union;
    names_t replacement_union;
    names_t responsibility_names;
    names_t cmake_markers;
    std::map<std::string, names_t> expected_responsibilities_by_path;
    const auto& cmake_graph = object_member(dead_paths, "cmake_graph", "public dead paths");
    const auto cmake_path = string_member(cmake_graph, "path", "dead-path CMake graph");
    const auto cmake_text = read_bounded(repository_file(root, cmake_path), k_maximum_source_bytes);
    for (const auto& retirement : retirements) {
        const auto responsibility = string_member(
            retirement, "responsibility", "dead-path retirement");
        require(responsibility_names.insert(responsibility).second,
                "dead-path responsibility is duplicated: " + responsibility);
        const auto authority_it = authority_responsibilities.find(responsibility);
        require(authority_it != authority_responsibilities.end(),
                "dead-path responsibility lacks authority: " + responsibility);
        const auto retired = names_from(
            object_member(retirement, "retired_paths", responsibility),
            responsibility + " retired paths");
        const auto responsibility_replacements = names_from(
            object_member(retirement, "replacement_paths", responsibility),
            responsibility + " replacement paths");
        require_exact_names(retired,
            names_from(object_member(*authority_it, "retired", responsibility),
                       responsibility + " authority retired paths"),
            responsibility + " retired paths");
        require_exact_names(responsibility_replacements,
            names_from(object_member(*authority_it, "replacements", responsibility),
                       responsibility + " authority replacement paths"),
            responsibility + " replacement paths");
        for (const auto& path : retired) {
            require(retired_union.insert(path).second,
                    "retired path is assigned to multiple responsibilities: " + path);
        }
        for (const auto& path : responsibility_replacements) {
            replacement_union.insert(path);
            expected_responsibilities_by_path[path].insert(responsibility);
        }
        const auto markers = names_from(
            object_member(retirement, "cmake_markers", responsibility),
            responsibility + " CMake markers");
        require(!markers.empty(), "dead-path responsibility has no CMake integration markers");
        for (const auto& marker : markers) {
            cmake_markers.insert(marker);
            require(cmake_text.find(marker) != std::string::npos,
                    "dead-path replacement is not bound in CMake for " + responsibility);
        }
    }
    require_exact_names(retired_union, absent, "retired path union");
    require_exact_names(replacement_union, replacements, "replacement path union");
    std::string marker_identity;
    for (auto it = cmake_markers.begin(); it != cmake_markers.end(); ++it) {
        if (it != cmake_markers.begin())
            marker_identity.push_back('\n');
        marker_identity += *it;
    }
    require(size_member(cmake_graph, "marker_count", "dead-path CMake graph") ==
                cmake_markers.size() &&
                string_member(cmake_graph, "marker_sha256", "dead-path CMake graph") ==
                    sha256_text(marker_identity),
            "dead-path CMake graph scoped marker identity mismatch");

    const auto& replacement_evidence = object_member(
        dead_paths, "replacement_evidence", "public dead paths");
    require(replacement_evidence.is_array() && replacement_evidence.size() == replacements.size(),
            "dead-path replacement evidence cardinality mismatch");
    names_t evidenced_replacements;
    for (const auto& row : replacement_evidence) {
        const auto path = string_member(row, "path", "replacement evidence");
        const auto hash = string_member(row, "sha256", "replacement evidence");
        require(evidenced_replacements.insert(path).second && replacements.count(path) == 1U,
                "replacement evidence contains a duplicate or unrelated path: " + path);
        require(evidence_hashes.count(path) == 1U && evidence_hashes.at(path) == hash,
                "replacement hash does not match current source evidence: " + path);
        require_exact_names(
            names_from(object_member(row, "responsibilities", "replacement evidence"),
                       path + " replacement responsibilities"),
            expected_responsibilities_by_path.at(path),
            path + " replacement responsibilities");
    }
    require_exact_names(evidenced_replacements, replacements, "evidenced replacement paths");
}

void verify_authority_cmake_integration(const std::filesystem::path& root) {
    const auto cmake = read_bounded(repository_file(
        root, "cmake/aida_c03_safe_headless_manifest.cmake"),
        k_maximum_source_bytes);
    const auto count_in = [](std::string_view text, std::string_view token) {
        require(!token.empty(), "CMake identity token is empty");
        std::size_t observed = 0;
        for (auto offset = text.find(token); offset != std::string_view::npos;
             offset = text.find(token, offset + token.size()))
            ++observed;
        return observed;
    };
    require(count_in(cmake, "aida_c03_register_manifest_entry(") == 57U &&
                count_in(cmake, "aida_c03_register_direct_test(") == 13U &&
                count_in(cmake, "add_test(NAME") == 3U &&
                count_in(cmake,
                    "add_test(NAME aida_c03_authority_surface_reproduction") == 1U &&
                count_in(cmake,
                    "set_tests_properties(aida_c03_authority_surface_reproduction PROPERTIES") == 1U &&
                cmake.find("aida_c03_mcp_contract_generator_reproduction") ==
                    std::string::npos,
            "authority CTest inventory is not the exact 15-test combined contract");
    const auto slice = [&](std::string_view begin_token, std::string_view end_token,
                           std::string_view identity) {
        const auto begin = cmake.find(begin_token);
        const auto end = begin == std::string::npos
            ? std::string::npos
            : cmake.find(end_token, begin + begin_token.size());
        require(begin != std::string::npos && end != std::string::npos && end > begin,
                std::string(identity) + " has stable source boundaries");
        return std::string_view(cmake).substr(begin, end - begin);
    };
    const auto authority_test = slice(
        "add_test(NAME aida_c03_authority_surface_reproduction",
        "get_property(_aida_compiler_harness_inputs", "authority CTest");
    for (const auto token : std::array<std::string_view, 10>{
             "COMMAND \"${Python3_EXECUTABLE}\"",
             "\"${CMAKE_SOURCE_DIR}/tools/c03_authority/verify_authority_surface_ledger.py\"",
             "--repository-root \"${CMAKE_SOURCE_DIR}\"",
             "--ledger \"${CMAKE_SOURCE_DIR}/tools/c03_authority/authority_surface_ledger.json\"",
             "--archive \"${_aida_authority_archive}\"",
             "--powershell \"${_aida_system_powershell}\"",
             "WORKING_DIRECTORY \"${CMAKE_CURRENT_SOURCE_DIR}\"",
             "TIMEOUT 600",
             "LABELS \"c03;c03_safe_headless;safe-headless;authority;surface;contract-reproduction\"",
             "RESOURCE_LOCK \"aida_c03_authority_surface_reproduction\""}) {
        require(authority_test.find(token) != std::string_view::npos,
                "authority CTest command or property is missing: " + std::string(token));
    }
    const std::array<std::string_view, 11> authority_inputs = {
        "tools/c03_authority/verify_authority_surface_ledger.py",
        "tools/c03_authority/authority_surface_ledger.json",
        "tools/generate_ida_mcp_contracts/generate_ida_mcp_contracts.py",
        "src/standalone/tests/analysis_workspace/generate_surface_manifest.ps1",
        "src/standalone/tests/analysis_workspace/standalone_surface_baseline.json",
        "src/standalone/tests/analysis_workspace/standalone_surface_final.json",
        "src/standalone/src/resources/mcp/ida_pro_mcp_2_0_0/contracts.json",
        "src/standalone/src/resources/mcp/ida_pro_mcp_2_0_0/effect_ledger.json",
        "src/standalone/src/resources/mcp/ida_pro_mcp_2_0_0/archive_manifest.json",
        "src/standalone/src/core/mcp/compat/ida_contracts_generated.hpp",
        "src/standalone/src/core/mcp/compat/ida_contracts_generated.cpp"
    };
    const auto repository_inputs = slice(
        "set(_aida_authority_repository_files",
        "aida_c03_require_sources(\"authority and surface reproduction\"",
        "authority repository inputs");
    const auto policy_inputs = slice(
        "set(_aida_policy_runtime",
        "foreach(_aida_relative IN LISTS _aida_policy_runtime)",
        "authority source-policy runtime inputs");
    for (const auto input : authority_inputs) {
        require(count_in(repository_inputs, input) == 1U &&
                    count_in(policy_inputs, input) == 1U,
                "authority input is missing or duplicated in CMake: " +
                    std::string(input));
    }
    for (const auto token : std::array<std::string_view, 13>{
             "if(NOT Python3_Interpreter_FOUND OR NOT Python3_EXECUTABLE)",
             "_aida_python_sha256", "_aida_system_powershell_sha256",
             "${_aida_system_root}/System32/WindowsPowerShell/v1.0/powershell.exe",
             "set(_aida_authority_archive \"C:/Users/ruar1337/ida-pro-mcp.zip\")",
             "3F7E7D9F534E3534C191D21251BBF0788DB14376C659488EA61681D48BC8D0F7",
             "CMAKE_CONFIGURE_DEPENDS", "${_aida_python_executable}",
             "${_aida_system_powershell}", "${_aida_authority_archive}",
             "foreach(_aida_authority_file IN LISTS _aida_authority_repository_files)",
             "file(SHA256 \"${_aida_authority_file}\" _aida_authority_file_sha256)",
             "string(SHA256 _aida_authority_identity"}) {
        require(cmake.find(token) != std::string::npos,
                "authority configure/hash binding is missing: " + std::string(token));
    }
}

}

authority_surface_ledger_result_t run_authority_surface_ledger_harness() {
    try {
        const auto root = repository_root();
        const auto ledger_path = repository_file(
            root, "tools/c03_authority/authority_surface_ledger.json");
        const auto ledger = read_json(ledger_path);
        const auto authority = verify_authority_ledger(ledger, root);
        const auto& reproduction = object_member(
            ledger, "current_surface_reproduction", "authority ledger");
        const auto& baseline_identity = object_member(
            reproduction, "baseline", "surface reproduction");
        const auto baseline = read_json(repository_file(
            root, string_member(baseline_identity, "path", "surface baseline")));
        const auto current = read_json(repository_file(
            root, string_member(reproduction, "checked_in_path", "surface reproduction")));

        const auto& generation = object_member(ledger, "contract_generation", "authority ledger");
        const auto& artifacts = object_member(generation, "artifacts", "contract generation");
        const auto contracts_artifact = read_json(repository_file(root, artifacts.at(0).get<std::string>()));
        const auto effects_artifact = read_json(repository_file(root, artifacts.at(1).get<std::string>()));
        const auto archive_manifest = read_json(repository_file(root, artifacts.at(2).get<std::string>()));
        const auto descriptors = verify_generated_descriptors(
            contracts_artifact, effects_artifact, archive_manifest, authority);
        verify_authority_cmake_integration(root);
        verify_legacy_preservation(baseline, current);
        verify_runtime_and_final_contract(ledger, current, authority, descriptors, root);
        verify_public_surfaces(ledger, current, root);
        return complete({true, {}});
    } catch (const std::exception& error) {
        return complete(fail(error.what()));
    }
}

}
