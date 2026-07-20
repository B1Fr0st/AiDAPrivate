#pragma once

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_set>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include <Windows.h>
#include <shlobj.h>
#endif

namespace aida::editor::programming_documents {

inline constexpr std::uint32_t journal_version = 1;
inline constexpr std::uint32_t session_version = 4;
inline constexpr std::size_t maximum_documents = 4096;
inline constexpr std::size_t normal_editable_document_bytes = 1ULL * 1024ULL * 1024ULL;
inline constexpr std::size_t maximum_editable_document_bytes = 1ULL * 1024ULL * 1024ULL;
inline constexpr std::size_t maximum_document_bytes = 8ULL * 1024ULL * 1024ULL;
inline constexpr std::size_t large_document_milestone_bytes = 50ULL * 1024ULL * 1024ULL;
inline constexpr std::size_t maximum_viewable_document_bytes = 500ULL * 1024ULL * 1024ULL;
inline constexpr std::size_t maximum_manifest_bytes = 4ULL * 1024ULL * 1024ULL;
inline constexpr std::size_t maximum_header_bytes = 64ULL * 1024ULL;

struct text_metadata_t {
    std::string encoding = "utf-8";
    std::string bom = "none";
    std::string eol = "lf";
};

struct text_decode_result_t {
    bool succeeded = false;
    std::string detail;
    std::string text;
    text_metadata_t metadata;
};

struct text_encode_result_t {
    bool succeeded = false;
    std::string detail;
    std::string bytes;
};

inline bool append_utf8(std::string& output, std::uint32_t codepoint) {
    if (codepoint > 0x10ffffU || (codepoint >= 0xd800U && codepoint <= 0xdfffU)) return false;
    if (codepoint <= 0x7fU) output.push_back(static_cast<char>(codepoint));
    else if (codepoint <= 0x7ffU) {
        output.push_back(static_cast<char>(0xc0U | (codepoint >> 6U)));
        output.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
    } else if (codepoint <= 0xffffU) {
        output.push_back(static_cast<char>(0xe0U | (codepoint >> 12U)));
        output.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
    } else {
        output.push_back(static_cast<char>(0xf0U | (codepoint >> 18U)));
        output.push_back(static_cast<char>(0x80U | ((codepoint >> 12U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
    }
    return true;
}

inline bool decode_utf8_codepoint(std::string_view input, std::size_t& index,
                                  std::uint32_t& codepoint) {
    if (index >= input.size()) return false;
    const auto first = static_cast<unsigned char>(input[index++]);
    if (first <= 0x7fU) { codepoint = first; return first != 0; }
    int continuation = 0;
    std::uint32_t value = 0;
    std::uint32_t minimum = 0;
    if ((first & 0xe0U) == 0xc0U) { continuation = 1; value = first & 0x1fU; minimum = 0x80U; }
    else if ((first & 0xf0U) == 0xe0U) { continuation = 2; value = first & 0x0fU; minimum = 0x800U; }
    else if ((first & 0xf8U) == 0xf0U) { continuation = 3; value = first & 0x07U; minimum = 0x10000U; }
    else return false;
    if (index + static_cast<std::size_t>(continuation) > input.size()) return false;
    for (int count = 0; count < continuation; ++count) {
        const auto next = static_cast<unsigned char>(input[index++]);
        if ((next & 0xc0U) != 0x80U) return false;
        value = (value << 6U) | (next & 0x3fU);
    }
    if (value < minimum || value > 0x10ffffU ||
        (value >= 0xd800U && value <= 0xdfffU)) return false;
    codepoint = value;
    return true;
}

inline text_decode_result_t decode_file_bytes(std::string_view bytes) {
    text_decode_result_t result;
    std::string decoded;
    std::size_t offset = 0;
    bool utf16 = false;
    bool little_endian = true;
    if (bytes.size() >= 3 && static_cast<unsigned char>(bytes[0]) == 0xefU &&
        static_cast<unsigned char>(bytes[1]) == 0xbbU &&
        static_cast<unsigned char>(bytes[2]) == 0xbfU) {
        result.metadata.bom = "utf-8";
        offset = 3;
    } else if (bytes.size() >= 2 && static_cast<unsigned char>(bytes[0]) == 0xffU &&
        static_cast<unsigned char>(bytes[1]) == 0xfeU) {
        result.metadata.encoding = "utf-16le";
        result.metadata.bom = "utf-16le";
        utf16 = true;
        offset = 2;
    } else if (bytes.size() >= 2 && static_cast<unsigned char>(bytes[0]) == 0xfeU &&
        static_cast<unsigned char>(bytes[1]) == 0xffU) {
        result.metadata.encoding = "utf-16be";
        result.metadata.bom = "utf-16be";
        utf16 = true;
        little_endian = false;
        offset = 2;
    }
    if (utf16) {
        if (((bytes.size() - offset) & 1U) != 0U) {
            result.detail = "The UTF-16 byte length is invalid.";
            return result;
        }
        auto unit_at = [&](std::size_t at) {
            const auto first = static_cast<unsigned char>(bytes[at]);
            const auto second = static_cast<unsigned char>(bytes[at + 1]);
            return static_cast<std::uint16_t>(little_endian
                ? first | (static_cast<std::uint16_t>(second) << 8U)
                : second | (static_cast<std::uint16_t>(first) << 8U));
        };
        while (offset < bytes.size()) {
            std::uint32_t codepoint = unit_at(offset);
            offset += 2;
            if (codepoint >= 0xd800U && codepoint <= 0xdbffU) {
                if (offset >= bytes.size()) { result.detail = "The UTF-16 surrogate pair is incomplete."; return result; }
                const std::uint32_t low = unit_at(offset);
                offset += 2;
                if (low < 0xdc00U || low > 0xdfffU) { result.detail = "The UTF-16 surrogate pair is invalid."; return result; }
                codepoint = 0x10000U + ((codepoint - 0xd800U) << 10U) + (low - 0xdc00U);
            } else if (codepoint >= 0xdc00U && codepoint <= 0xdfffU) {
                result.detail = "The UTF-16 surrogate sequence is invalid.";
                return result;
            }
            if (codepoint == 0 || !append_utf8(decoded, codepoint)) {
                result.detail = "The text contains unsupported NUL or Unicode scalar values.";
                return result;
            }
        }
    } else {
        const std::string_view payload = bytes.substr(offset);
        std::size_t cursor = 0;
        while (cursor < payload.size()) {
            std::uint32_t codepoint = 0;
            if (!decode_utf8_codepoint(payload, cursor, codepoint)) {
                result.detail = "The file is not valid UTF-8/UTF-16 text; open it in Hex View or Binary Map.";
                return result;
            }
        }
        decoded.assign(payload);
    }
    std::size_t crlf = 0;
    std::size_t cr = 0;
    std::size_t lf = 0;
    std::string normalized;
    normalized.reserve(decoded.size());
    for (std::size_t index = 0; index < decoded.size(); ++index) {
        if (decoded[index] == '\r') {
            if (index + 1 < decoded.size() && decoded[index + 1] == '\n') { ++crlf; ++index; }
            else ++cr;
            normalized.push_back('\n');
        } else {
            if (decoded[index] == '\n') ++lf;
            normalized.push_back(decoded[index]);
        }
    }
    result.metadata.eol = crlf >= lf && crlf >= cr && crlf != 0 ? "crlf"
        : cr > lf && cr != 0 ? "cr" : "lf";
    result.text = std::move(normalized);
    result.succeeded = true;
    return result;
}

inline text_encode_result_t encode_file_text(std::string_view text,
                                             const text_metadata_t& metadata) {
    text_encode_result_t result;
    if (metadata.encoding != "utf-8" && metadata.encoding != "utf-16le" &&
        metadata.encoding != "utf-16be") {
        result.detail = "The original text encoding is unsupported for an exact save.";
        return result;
    }
    std::string eol_text;
    const std::string_view separator = metadata.eol == "crlf" ? "\r\n" :
        metadata.eol == "cr" ? "\r" : "\n";
    eol_text.reserve(text.size() + text.size() / 16U);
    for (const char character : text) {
        if (character == '\n') eol_text.append(separator);
        else if (character != '\r') eol_text.push_back(character);
    }
    if (metadata.encoding == "utf-8") {
        std::size_t cursor = 0;
        while (cursor < eol_text.size()) {
            std::uint32_t codepoint = 0;
            if (!decode_utf8_codepoint(eol_text, cursor, codepoint)) {
                result.detail = "The editor contains invalid UTF-8 and cannot be saved losslessly.";
                return result;
            }
        }
        if (metadata.bom == "utf-8") result.bytes.append("\xef\xbb\xbf", 3);
        result.bytes.append(eol_text);
        result.succeeded = true;
        return result;
    }
    const bool little = metadata.encoding == "utf-16le";
    if (metadata.bom == "utf-16le") result.bytes.append("\xff\xfe", 2);
    else if (metadata.bom == "utf-16be") result.bytes.append("\xfe\xff", 2);
    auto append_unit = [&](std::uint16_t unit) {
        if (little) {
            result.bytes.push_back(static_cast<char>(unit & 0xffU));
            result.bytes.push_back(static_cast<char>(unit >> 8U));
        } else {
            result.bytes.push_back(static_cast<char>(unit >> 8U));
            result.bytes.push_back(static_cast<char>(unit & 0xffU));
        }
    };
    std::size_t cursor = 0;
    while (cursor < eol_text.size()) {
        std::uint32_t codepoint = 0;
        if (!decode_utf8_codepoint(eol_text, cursor, codepoint)) {
            result.detail = "The editor contains invalid UTF-8 and cannot be converted to UTF-16 losslessly.";
            return result;
        }
        if (codepoint <= 0xffffU) append_unit(static_cast<std::uint16_t>(codepoint));
        else {
            codepoint -= 0x10000U;
            append_unit(static_cast<std::uint16_t>(0xd800U + (codepoint >> 10U)));
            append_unit(static_cast<std::uint16_t>(0xdc00U + (codepoint & 0x3ffU)));
        }
    }
    result.succeeded = true;
    return result;
}

struct document_record_t {
    std::string filename;
    std::string canonical_path;
    std::string original_path;
    std::uint64_t document_id = 0;
    std::uint64_t base_fingerprint = 0;
    std::uint64_t revision = 1;
    std::uint64_t content_hash = 0;
    std::uint64_t byte_length = 0;
    std::uint32_t group_id = 0;
    bool pinned = false;
    bool dirty = false;
    int caret_line = 0;
    int caret_column = 0;
    int selection_anchor_line = 0;
    int selection_anchor_column = 0;
    bool selection_active = false;
    float scroll_x = 0.f;
    float scroll_y = 0.f;
    std::vector<int> folded_lines;
    std::string language_override;
    text_metadata_t text;
    std::string content;
};

struct navigation_record_t {
    std::uint64_t document_id = 0;
    int line = 0;
    int column = 0;
};

struct group_record_t {
    std::uint32_t group_id = 0;
    std::uint64_t active_document_id = 0;
    std::vector<navigation_record_t> back;
    std::vector<navigation_record_t> forward;
};

struct session_state_t {
    std::vector<document_record_t> documents;
    std::vector<group_record_t> groups;
    std::uint64_t active_document_id = 0;
    bool migrated_legacy = false;
};

struct recovery_reference_t {
    bool available = false;
    std::string journal_file;
    std::string previous_file;
    document_record_t metadata;
    std::string diagnostic;
};

struct operation_result_t {
    bool succeeded = false;
    std::string detail;
    bool changed = false;
};

struct recovery_load_result_t : operation_result_t {
    document_record_t document;
};

inline std::mutex& storage_mutex() {
    static std::mutex value;
    return value;
}

inline std::uint64_t fingerprint(std::string_view content) {
    std::uint64_t hash = 14695981039346656037ULL;
    for (const char character : content) {
        hash ^= static_cast<unsigned char>(character);
        hash *= 1099511628211ULL;
    }
    hash ^= static_cast<std::uint64_t>(content.size());
    hash *= 1099511628211ULL;
    return hash == 0 ? 1 : hash;
}

inline std::string canonical_path(const std::string& raw) {
    if (raw.empty())
        return {};
    std::string value = std::filesystem::path(raw).lexically_normal().generic_string();
#if defined(_WIN32)
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
#endif
    return value;
}

inline bool valid_journal_filename(std::string_view filename) {
    if (filename.size() != 67 || filename.substr(59) != ".journal" ||
        filename[16] != '-' || filename[33] != '-' || filename[42] != '-')
        return false;
    for (std::size_t index = 0; index < 59; ++index) {
        if (index == 16 || index == 33 || index == 42) continue;
        const unsigned char character = static_cast<unsigned char>(filename[index]);
        if (!std::isxdigit(character)) return false;
    }
    return true;
}

inline text_metadata_t inspect_text(std::string_view content) {
    text_metadata_t result;
    if (content.size() >= 3 && static_cast<unsigned char>(content[0]) == 0xef &&
        static_cast<unsigned char>(content[1]) == 0xbb &&
        static_cast<unsigned char>(content[2]) == 0xbf) {
        result.bom = "utf-8";
    } else if (content.size() >= 2 && static_cast<unsigned char>(content[0]) == 0xff &&
               static_cast<unsigned char>(content[1]) == 0xfe) {
        result.encoding = "utf-16le";
        result.bom = "utf-16le";
    } else if (content.size() >= 2 && static_cast<unsigned char>(content[0]) == 0xfe &&
               static_cast<unsigned char>(content[1]) == 0xff) {
        result.encoding = "utf-16be";
        result.bom = "utf-16be";
    }
    std::size_t crlf = 0;
    std::size_t lf = 0;
    std::size_t cr = 0;
    for (std::size_t index = 0; index < content.size(); ++index) {
        if (content[index] == '\r') {
            if (index + 1 < content.size() && content[index + 1] == '\n') {
                ++crlf;
                ++index;
            } else {
                ++cr;
            }
        } else if (content[index] == '\n') {
            ++lf;
        }
    }
    if (crlf >= lf && crlf >= cr && crlf != 0)
        result.eol = "crlf";
    else if (cr > lf && cr != 0)
        result.eol = "cr";
    else
        result.eol = "lf";
    return result;
}

inline nlohmann::json record_metadata_json(const document_record_t& record) {
    return {
        {"filename", record.filename},
        {"path", record.canonical_path},
        {"document_id", record.document_id},
        {"base_fingerprint", record.base_fingerprint},
        {"revision", record.revision},
        {"encoding", record.text.encoding},
        {"bom", record.text.bom},
        {"eol", record.text.eol},
        {"dirty_content_hash", record.content_hash},
        {"byte_length", record.byte_length},
        {"group_id", record.group_id},
        {"pinned", record.pinned},
        {"caret_line", record.caret_line},
        {"caret_column", record.caret_column},
        {"selection_anchor_line", record.selection_anchor_line},
        {"selection_anchor_column", record.selection_anchor_column},
        {"selection_active", record.selection_active},
        {"scroll_x", record.scroll_x},
        {"scroll_y", record.scroll_y},
        {"folded_lines", record.folded_lines},
        {"language_override", record.language_override}
    };
}

inline bool bounded_string(const nlohmann::json& object, const char* key,
                           std::string& output, std::size_t limit) {
    const auto found = object.find(key);
    if (found == object.end() || !found->is_string())
        return false;
    output = found->get<std::string>();
    return output.size() <= limit;
}

inline bool parse_record_metadata(const nlohmann::json& object, document_record_t& record,
                                  std::string& error) {
    if (!object.is_object() ||
        !bounded_string(object, "filename", record.filename, 1024) ||
        !bounded_string(object, "path", record.canonical_path, 32768) ||
        !bounded_string(object, "encoding", record.text.encoding, 32) ||
        !bounded_string(object, "bom", record.text.bom, 32) ||
        !bounded_string(object, "eol", record.text.eol, 16)) {
        error = "Recovery metadata is incomplete or exceeds its bounds.";
        return false;
    }
    record.document_id = object.value("document_id", std::uint64_t{0});
    record.base_fingerprint = object.value("base_fingerprint", std::uint64_t{0});
    record.revision = object.value("revision", std::uint64_t{0});
    record.content_hash = object.value("dirty_content_hash", std::uint64_t{0});
    record.byte_length = object.value("byte_length", std::uint64_t{0});
    record.group_id = object.value("group_id", std::uint32_t{0});
    record.pinned = object.value("pinned", false);
    record.caret_line = object.value("caret_line", 0);
    record.caret_column = object.value("caret_column", 0);
    record.selection_anchor_line = object.value("selection_anchor_line", record.caret_line);
    record.selection_anchor_column = object.value("selection_anchor_column", record.caret_column);
    record.selection_active = object.value("selection_active", false);
    record.scroll_x = object.value("scroll_x", 0.f);
    record.scroll_y = object.value("scroll_y", 0.f);
    record.folded_lines = object.value("folded_lines", std::vector<int>{});
    record.language_override = object.value("language_override", std::string{});
    if (record.document_id == 0 || record.revision == 0 || record.content_hash == 0 ||
        record.byte_length > maximum_document_bytes || record.caret_line < 0 ||
        record.caret_column < 0 || record.selection_anchor_line < 0 ||
        record.selection_anchor_column < 0 || record.scroll_x < 0.f || record.scroll_y < 0.f ||
        record.folded_lines.size() > 4096 || record.language_override.size() > 64 ||
        std::any_of(record.folded_lines.begin(), record.folded_lines.end(),
            [](int line) { return line < 0; })) {
        error = "Recovery metadata contains an invalid identity, revision, size, or editor position.";
        return false;
    }
    record.canonical_path = canonical_path(record.canonical_path);
    return true;
}

inline std::filesystem::path storage_directory() {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    return {};
#else
    wchar_t* appdata = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata)))
        return {};
    auto path = std::filesystem::path(appdata) / L"AiDA" / L"Standalone" /
        L"programming_documents";
    CoTaskMemFree(appdata);
    std::error_code ec;
    std::filesystem::create_directories(path, ec);
    return ec ? std::filesystem::path{} : path;
#endif
}

inline std::filesystem::path manifest_path() {
    const auto directory = storage_directory();
    return directory.empty() ? std::filesystem::path{} : directory / L"recovery-manifest.json";
}

inline std::filesystem::path previous_manifest_path() {
    const auto directory = storage_directory();
    return directory.empty() ? std::filesystem::path{} : directory / L"recovery-manifest.previous.json";
}

inline operation_result_t read_bounded_file(const std::filesystem::path& path,
                                            std::size_t limit, std::string& output) {
    output.clear();
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    if (ec)
        return {false, "The file is unavailable: " + ec.message()};
    if (size > limit)
        return {false, "The file exceeds its verified size limit."};
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open())
        return {false, "The file could not be opened."};
    output.resize(static_cast<std::size_t>(size));
    if (!output.empty())
        input.read(output.data(), static_cast<std::streamsize>(output.size()));
    if ((!output.empty() && input.gcount() != static_cast<std::streamsize>(output.size())) ||
        input.bad()) {
        output.clear();
        return {false, "The complete file could not be read."};
    }
    return {true, {}};
}

inline operation_result_t atomic_exact_write(const std::filesystem::path& destination,
                                             std::string_view bytes) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    static_cast<void>(destination);
    static_cast<void>(bytes);
    return {true, {}};
#else
    if (destination.empty())
        return {false, "The recovery destination is unavailable."};
    std::error_code ec;
    std::filesystem::create_directories(destination.parent_path(), ec);
    if (ec)
        return {false, "The recovery directory could not be created: " + ec.message()};
    static std::atomic<std::uint64_t> sequence{1};
    std::filesystem::path temporary;
    HANDLE handle = INVALID_HANDLE_VALUE;
    DWORD create_error = ERROR_SUCCESS;
    for (int attempt = 0; attempt < 64 && handle == INVALID_HANDLE_VALUE; ++attempt) {
        temporary = destination;
        temporary += L".tmp-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
            std::to_wstring(sequence.fetch_add(1, std::memory_order_relaxed));
        handle = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
            FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH, nullptr);
        create_error = GetLastError();
    }
    if (handle == INVALID_HANDLE_VALUE)
        return {false, "An exclusive recovery temporary file could not be created (Win32 " +
            std::to_string(create_error) + ")."};
    bool complete = true;
    DWORD failure = ERROR_SUCCESS;
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const DWORD requested = static_cast<DWORD>((std::min)(bytes.size() - offset,
            static_cast<std::size_t>(0x7ffff000U)));
        DWORD written = 0;
        if (!WriteFile(handle, bytes.data() + offset, requested, &written, nullptr) ||
            written != requested) {
            complete = false;
            failure = GetLastError();
            break;
        }
        offset += written;
    }
    if (complete && !FlushFileBuffers(handle)) {
        complete = false;
        failure = GetLastError();
    }
    if (!CloseHandle(handle) && complete) {
        complete = false;
        failure = GetLastError();
    }
    if (complete) {
        const auto exact = std::filesystem::file_size(temporary, ec);
        if (ec || exact != bytes.size()) {
            complete = false;
            failure = ec ? static_cast<DWORD>(ec.value()) : ERROR_WRITE_FAULT;
        }
    }
    if (!complete) {
        DeleteFileW(temporary.c_str());
        return {false, "The recovery file was not written and flushed completely (Win32 " +
            std::to_string(failure) + ")."};
    }
    const bool exists = std::filesystem::exists(destination, ec) && !ec;
    const BOOL moved = exists
        ? ReplaceFileW(destination.c_str(), temporary.c_str(), nullptr,
            REPLACEFILE_WRITE_THROUGH, nullptr, nullptr)
        : MoveFileExW(temporary.c_str(), destination.c_str(), MOVEFILE_WRITE_THROUGH);
    if (!moved) {
        const DWORD error = GetLastError();
        DeleteFileW(temporary.c_str());
        return {false, "Atomic recovery replacement failed (Win32 " +
            std::to_string(error) + ")."};
    }
    return {true, {}, true};
#endif
}

inline operation_result_t load_manifest(nlohmann::json& manifest,
                                        bool allow_previous = true) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    static_cast<void>(allow_previous);
    manifest = {{"schema", "aida.programming-recovery-manifest"},
                {"version", journal_version}, {"entries", nlohmann::json::array()}};
    return {true, {}};
#else
    const auto current = manifest_path();
    if (current.empty())
        return {false, "The programming recovery directory is unavailable."};
    const auto try_path = [&](const std::filesystem::path& candidate,
                              nlohmann::json& parsed) -> operation_result_t {
        std::string raw;
        const auto read = read_bounded_file(candidate, maximum_manifest_bytes, raw);
        if (!read.succeeded)
            return read;
        parsed = nlohmann::json::parse(raw, nullptr, false);
        if (parsed.is_discarded() || !parsed.is_object() ||
            parsed.value("schema", std::string{}) != "aida.programming-recovery-manifest" ||
            parsed.value("version", 0U) != journal_version ||
            !parsed.contains("entries") || !parsed["entries"].is_array() ||
            parsed["entries"].size() > maximum_documents)
            return {false, "The recovery manifest is corrupt, unsupported, or over capacity."};
        return {true, {}};
    };
    auto loaded = try_path(current, manifest);
    if (loaded.succeeded)
        return loaded;
    if (allow_previous) {
        auto previous = try_path(previous_manifest_path(), manifest);
        if (previous.succeeded) {
            previous.detail = "The last-good recovery manifest was used because the current manifest was rejected.";
            return previous;
        }
    }
    std::error_code ec;
    if (!std::filesystem::exists(current, ec) && !std::filesystem::exists(previous_manifest_path(), ec)) {
        manifest = {{"schema", "aida.programming-recovery-manifest"},
                    {"version", journal_version}, {"entries", nlohmann::json::array()}};
        return {true, {}};
    }
    return loaded;
#endif
}

inline operation_result_t write_manifest(const nlohmann::json& manifest) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    static_cast<void>(manifest);
    return {true, {}};
#else
    const auto current = manifest_path();
    if (current.empty())
        return {false, "The programming recovery directory is unavailable."};
    std::error_code ec;
    if (std::filesystem::exists(current, ec) && !ec) {
        std::string old_manifest;
        const auto read = read_bounded_file(current, maximum_manifest_bytes, old_manifest);
        if (read.succeeded) {
            const auto parsed = nlohmann::json::parse(old_manifest, nullptr, false);
            const bool valid = !parsed.is_discarded() && parsed.is_object() &&
                parsed.value("schema", std::string{}) ==
                    "aida.programming-recovery-manifest" &&
                parsed.value("version", 0U) == journal_version &&
                parsed.contains("entries") && parsed["entries"].is_array() &&
                parsed["entries"].size() <= maximum_documents;
            if (valid) {
                const auto retained = atomic_exact_write(previous_manifest_path(), old_manifest);
                if (!retained.succeeded)
                    return {false, "The last-good recovery manifest could not be retained: " + retained.detail};
            }
        }
    }
    const std::string raw = manifest.dump();
    if (raw.size() > maximum_manifest_bytes)
        return {false, "The recovery manifest exceeds its verified size limit."};
    return atomic_exact_write(current, raw);
#endif
}

inline std::string journal_blob(const document_record_t& source) {
    document_record_t record = source;
    record.canonical_path = canonical_path(record.canonical_path);
    record.byte_length = record.content.size();
    record.content_hash = fingerprint(record.content);
    const std::string header = nlohmann::json({
        {"schema", "aida.programming-recovery-journal"},
        {"version", journal_version},
        {"document", record_metadata_json(record)}
    }).dump();
    std::string result;
    result.reserve(16 + header.size() + record.content.size());
    result.append("AIDAJRNL", 8);
    const std::uint32_t length = static_cast<std::uint32_t>(header.size());
    for (unsigned shift = 0; shift < 32; shift += 8)
        result.push_back(static_cast<char>((length >> shift) & 0xffU));
    result.append(header);
    result.append(record.content);
    return result;
}

inline recovery_load_result_t load_journal_file(const std::string& filename,
                                                bool include_content) {
    recovery_load_result_t result;
    if (!valid_journal_filename(filename)) {
        result.detail = "The recovery journal filename is invalid.";
        return result;
    }
    const auto directory = storage_directory();
    if (directory.empty()) {
        result.detail = "The programming recovery directory is unavailable.";
        return result;
    }
    std::string raw;
    const auto read = read_bounded_file(directory / filename,
        maximum_document_bytes + maximum_header_bytes + 12U, raw);
    if (!read.succeeded) {
        result.detail = read.detail;
        return result;
    }
    if (raw.size() < 12 || raw.compare(0, 8, "AIDAJRNL") != 0) {
        result.detail = "The recovery journal signature is invalid.";
        return result;
    }
    std::uint32_t header_length = 0;
    for (unsigned shift = 0; shift < 32; shift += 8)
        header_length |= static_cast<std::uint32_t>(
            static_cast<unsigned char>(raw[8 + shift / 8])) << shift;
    if (header_length == 0 || header_length > maximum_header_bytes ||
        12ULL + header_length > raw.size()) {
        result.detail = "The recovery journal header length is invalid.";
        return result;
    }
    using raw_difference_t = std::string::difference_type;
    const auto header = nlohmann::json::parse(
        raw.begin() + static_cast<raw_difference_t>(12U),
        raw.begin() + static_cast<raw_difference_t>(12U + header_length), nullptr, false);
    if (header.is_discarded() || !header.is_object() ||
        header.value("schema", std::string{}) != "aida.programming-recovery-journal" ||
        header.value("version", 0U) != journal_version ||
        !header.contains("document")) {
        result.detail = "The recovery journal schema or version is unsupported.";
        return result;
    }
    std::string parse_error;
    if (!parse_record_metadata(header["document"], result.document, parse_error)) {
        result.detail = std::move(parse_error);
        return result;
    }
    const std::size_t payload_offset = 12U + header_length;
    const std::size_t payload_length = raw.size() - payload_offset;
    if (payload_length != result.document.byte_length) {
        result.detail = "The recovery journal byte length does not match its metadata.";
        return result;
    }
    const std::string_view payload(raw.data() + payload_offset, payload_length);
    if (fingerprint(payload) != result.document.content_hash) {
        result.detail = "The recovery journal content hash is invalid.";
        return result;
    }
    if (include_content)
        result.document.content.assign(payload);
    result.succeeded = true;
    return result;
}

inline operation_result_t commit(const document_record_t& source) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    static_cast<void>(source);
    return {true, {}};
#else
    std::lock_guard<std::mutex> lock(storage_mutex());
    if (!source.dirty || source.document_id == 0 || source.revision == 0 ||
        source.content.size() > maximum_document_bytes)
        return {false, "Only bounded dirty documents with stable identities can be journaled."};
    document_record_t record = source;
    record.canonical_path = canonical_path(record.canonical_path);
    record.byte_length = record.content.size();
    record.content_hash = fingerprint(record.content);
    nlohmann::json manifest;
    const auto loaded = load_manifest(manifest);
    if (!loaded.succeeded)
        return loaded;
    auto& entries = manifest["entries"];
    std::size_t selected = entries.size();
    for (std::size_t index = 0; index < entries.size(); ++index) {
        if (!entries[index].is_object())
            continue;
        const auto existing_id = entries[index].value("document_id", std::uint64_t{0});
        const auto existing_path = canonical_path(entries[index].value("path", std::string{}));
        if (existing_id == record.document_id ||
            (!record.canonical_path.empty() && existing_path == record.canonical_path)) {
            selected = index;
            break;
        }
    }
    if (selected < entries.size()) {
        const auto retained_document_id =
            entries[selected].value("document_id", std::uint64_t{0});
        const bool same_document = retained_document_id == record.document_id;
        const bool retained_payload =
            !entries[selected].value("current", std::string{}).empty();
        if (!same_document && retained_payload)
            return {false, "A recovery journal for the same path belongs to another document identity; review or discard it before checkpointing new edits."};
        const auto clean_revision =
            entries[selected].value("clean_revision", std::uint64_t{0});
        if (same_document && clean_revision >= record.revision)
            return {true, "A confirmed clean/discard outcome supersedes this recovery revision."};
        const auto retained_revision = entries[selected].value("revision", std::uint64_t{0});
        const auto retained_hash = entries[selected].value("dirty_content_hash", std::uint64_t{0});
        if (same_document && retained_revision > record.revision)
            return {true, "A newer recovery revision is already retained."};
        if (same_document && retained_revision == record.revision && retained_hash == record.content_hash)
            return {true, "The exact recovery revision is already retained."};
        if (same_document && retained_revision == record.revision && retained_hash != 0 &&
            retained_hash != record.content_hash)
            return {false, "A different payload claimed the same recovery revision; the retained journal was preserved."};
    }
    if (selected == entries.size() && entries.size() >= maximum_documents)
        return {false, "The recovery manifest reached its document capacity."};
    static std::atomic<std::uint64_t> sequence{1};
    FILETIME system_time{};
    GetSystemTimeAsFileTime(&system_time);
    const std::uint64_t timestamp =
        (static_cast<std::uint64_t>(system_time.dwHighDateTime) << 32U) |
        system_time.dwLowDateTime;
    const auto nonce = sequence.fetch_add(1, std::memory_order_relaxed);
    const std::uint64_t key = fingerprint(record.canonical_path + "#" +
        std::to_string(record.document_id));
    char filename[128]{};
    std::snprintf(filename, sizeof(filename), "%016llx-%016llx-%08lx-%016llx.journal",
        static_cast<unsigned long long>(key), static_cast<unsigned long long>(timestamp),
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long long>(nonce));
    const auto directory = storage_directory();
    const std::string blob = journal_blob(record);
    const auto journal_written = atomic_exact_write(directory / filename, blob);
    if (!journal_written.succeeded)
        return journal_written;
    nlohmann::json replacement = record_metadata_json(record);
    replacement["current"] = filename;
    replacement["previous"] = selected < entries.size()
        ? entries[selected].value("current", std::string{}) : std::string{};
    if (selected < entries.size())
        entries[selected] = std::move(replacement);
    else
        entries.push_back(std::move(replacement));
    const auto manifest_written = write_manifest(manifest);
    if (!manifest_written.succeeded) {
        std::error_code cleanup_error;
        std::filesystem::remove(directory / filename, cleanup_error);
        return manifest_written;
    }
    std::unordered_set<std::string> retained;
    const auto collect = [&retained](const nlohmann::json& source) {
        if (!source.is_object() || !source.contains("entries") ||
            !source["entries"].is_array()) return;
        for (const auto& entry : source["entries"]) {
            if (!entry.is_object()) continue;
            const auto current = entry.value("current", std::string{});
            const auto previous = entry.value("previous", std::string{});
            if (valid_journal_filename(current)) retained.insert(current);
            if (valid_journal_filename(previous)) retained.insert(previous);
        }
    };
    collect(manifest);
    std::string previous_raw;
    if (read_bounded_file(previous_manifest_path(), maximum_manifest_bytes,
            previous_raw).succeeded) {
        const auto previous_manifest = nlohmann::json::parse(previous_raw, nullptr, false);
        if (!previous_manifest.is_discarded())
            collect(previous_manifest);
    }
    std::error_code cleanup_error;
    for (std::filesystem::directory_iterator iterator(directory, cleanup_error), end;
         !cleanup_error && iterator != end; iterator.increment(cleanup_error)) {
        if (!iterator->is_regular_file(cleanup_error) || cleanup_error) break;
        if (iterator->path().extension() != L".journal") continue;
        const std::string candidate = iterator->path().filename().string();
        if (!valid_journal_filename(candidate)) continue;
        if (retained.find(candidate) == retained.end()) {
            std::error_code remove_error;
            std::filesystem::remove(iterator->path(), remove_error);
        }
    }
    return {true, {}, true};
#endif
}

inline operation_result_t migrate_legacy_snapshot(document_record_t identity,
                                                   const std::string& original_path = {}) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    static_cast<void>(identity);
    static_cast<void>(original_path);
    return {true, {}};
#else
    if (identity.canonical_path.empty() || identity.document_id == 0)
        return {true, {}};
    const auto directory = storage_directory();
    if (directory.empty())
        return {false, "The programming recovery directory is unavailable."};
    std::error_code ec;
    std::vector<std::string> paths{identity.canonical_path};
    if (!original_path.empty() && original_path != identity.canonical_path)
        paths.push_back(original_path);
    std::filesystem::path legacy;
    for (const auto& path : paths) {
        std::uint64_t key = 0xCBF29CE484222325ULL;
        for (const char character : path) {
            key ^= static_cast<unsigned char>(character);
            key *= 0x100000001B3ULL;
        }
        char name[40]{};
        std::snprintf(name, sizeof(name), "%016llx.snapshot",
            static_cast<unsigned long long>(key));
        const auto candidate = directory.parent_path() / L"hot_exit" / name;
        ec.clear();
        if (std::filesystem::exists(candidate, ec) && !ec) {
            legacy = candidate;
            break;
        }
    }
    if (legacy.empty())
        return {true, {}};
    std::string content;
    const auto read = read_bounded_file(legacy, maximum_document_bytes, content);
    if (!read.succeeded)
        return {false, "Legacy recovery snapshot rejected: " + read.detail};
    identity.content = std::move(content);
    identity.dirty = true;
    identity.byte_length = identity.content.size();
    identity.content_hash = fingerprint(identity.content);
    identity.text = inspect_text(identity.content);
    const auto migrated = commit(identity);
    if (!migrated.succeeded)
        return {false, "Legacy recovery snapshot could not be migrated: " + migrated.detail};
    if (!migrated.changed)
        return {true, "Legacy recovery snapshot was retained because no new journal commit was required: " + migrated.detail};
    std::filesystem::remove(legacy, ec);
    if (ec)
        return {true, "Legacy recovery was migrated, but the superseded snapshot could not be removed: " + ec.message()};
    return {true, "Legacy recovery snapshot migrated to the versioned journal."};
#endif
}

inline recovery_reference_t probe(std::uint64_t document_id, const std::string& path) {
    recovery_reference_t result;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    static_cast<void>(document_id);
    static_cast<void>(path);
    return result;
#else
    std::lock_guard<std::mutex> lock(storage_mutex());
    nlohmann::json manifest;
    const auto loaded = load_manifest(manifest);
    if (!loaded.succeeded) {
        result.diagnostic = loaded.detail;
        return result;
    }
    result.diagnostic = loaded.detail;
    const std::string expected_path = canonical_path(path);
    for (const auto& entry : manifest["entries"]) {
        if (!entry.is_object())
            continue;
        const auto entry_id = entry.value("document_id", std::uint64_t{0});
        const auto entry_path = canonical_path(entry.value("path", std::string{}));
        if (entry_id != document_id &&
            (expected_path.empty() || entry_path != expected_path))
            continue;
        if (entry.value("clean_revision", std::uint64_t{0}) != 0 &&
            entry.value("current", std::string{}).empty())
            return result;
        const std::string current = entry.value("current", std::string{});
        const std::string previous = entry.value("previous", std::string{});
        auto verified = load_journal_file(current, false);
        std::string rejection;
        if (!verified.succeeded) {
            rejection = verified.detail;
            verified = load_journal_file(previous, false);
            if (!verified.succeeded) {
                result.diagnostic = "Current recovery journal rejected: " + rejection +
                    " Last-good journal rejected: " + verified.detail;
                return result;
            }
            result.journal_file = previous;
            const std::string journal_diagnostic =
                "The last-good journal is offered because the newest journal was rejected: " + rejection;
            result.diagnostic = result.diagnostic.empty() ? journal_diagnostic
                : result.diagnostic + " " + journal_diagnostic;
        } else {
            result.journal_file = current;
            result.previous_file = previous;
        }
        result.metadata = std::move(verified.document);
        result.available = true;
        return result;
    }
    return result;
#endif
}

inline recovery_load_result_t load(const recovery_reference_t& reference) {
    if (!reference.available) {
        recovery_load_result_t result;
        result.detail = "No verified recovery journal is available.";
        return result;
    }
    return load_journal_file(reference.journal_file, true);
}

inline operation_result_t discard(const recovery_reference_t& reference,
                                  std::uint64_t clean_revision = 0) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    static_cast<void>(reference);
    static_cast<void>(clean_revision);
    return {true, {}};
#else
    std::lock_guard<std::mutex> lock(storage_mutex());
    if (!reference.available)
        return {false, "No verified recovery journal is available."};
    nlohmann::json manifest;
    const auto loaded = load_manifest(manifest);
    if (!loaded.succeeded)
        return loaded;
    auto& entries = manifest["entries"];
    auto found = std::find_if(entries.begin(), entries.end(), [&](const nlohmann::json& entry) {
        if (!entry.is_object()) return false;
        if (entry.value("document_id", std::uint64_t{0}) == reference.metadata.document_id)
            return true;
        return !reference.metadata.canonical_path.empty() &&
            canonical_path(entry.value("path", std::string{})) ==
                reference.metadata.canonical_path;
    });
    std::string current = reference.journal_file;
    std::string previous = reference.previous_file;
    clean_revision = (std::max)(clean_revision, reference.metadata.revision);
    if (found != entries.end()) {
        current = found->value("current", current);
        previous = found->value("previous", previous);
        const auto retained_revision = found->value("revision", std::uint64_t{0});
        const bool exact_file = reference.journal_file == current ||
            reference.journal_file == previous;
        if (!exact_file || retained_revision > reference.metadata.revision)
            return {false, "A newer or different recovery journal replaced the confirmed identity; it was preserved."};
        nlohmann::json tombstone = record_metadata_json(reference.metadata);
        tombstone["document_id"] = reference.metadata.document_id;
        tombstone["path"] = reference.metadata.canonical_path;
        tombstone["revision"] = clean_revision;
        tombstone["clean_revision"] = clean_revision;
        tombstone["current"] = "";
        tombstone["previous"] = "";
        *found = std::move(tombstone);
    } else {
        if (entries.size() >= maximum_documents)
            return {false, "The recovery manifest reached its document capacity."};
        nlohmann::json tombstone = record_metadata_json(reference.metadata);
        tombstone["document_id"] = reference.metadata.document_id;
        tombstone["path"] = reference.metadata.canonical_path;
        tombstone["revision"] = clean_revision;
        tombstone["clean_revision"] = clean_revision;
        tombstone["current"] = "";
        tombstone["previous"] = "";
        entries.push_back(std::move(tombstone));
    }
    const auto persisted = write_manifest(manifest);
    if (!persisted.succeeded)
        return persisted;
    const std::string sealed = manifest.dump();
    const auto sealed_previous = atomic_exact_write(previous_manifest_path(), sealed);
    if (!sealed_previous.succeeded)
        return {false, "The discarded identity could not be removed from the last-good manifest: " +
            sealed_previous.detail};
    const auto directory = storage_directory();
    std::error_code ec;
    if (valid_journal_filename(current)) std::filesystem::remove(directory / current, ec);
    ec.clear();
    if (valid_journal_filename(previous)) std::filesystem::remove(directory / previous, ec);
    return {true, {}};
#endif
}

inline operation_result_t seal_clean_outcome(document_record_t identity,
                                              std::uint64_t clean_revision) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    static_cast<void>(identity);
    static_cast<void>(clean_revision);
    return {true, {}};
#else
    if (identity.document_id == 0 || clean_revision == 0)
        return {false, "The clean programming-document outcome has no stable identity or revision."};
    identity.canonical_path = canonical_path(identity.canonical_path);
    std::lock_guard<std::mutex> lock(storage_mutex());
    nlohmann::json manifest;
    const auto loaded = load_manifest(manifest);
    if (!loaded.succeeded)
        return loaded;
    auto& entries = manifest["entries"];
    auto found = std::find_if(entries.begin(), entries.end(), [&](const nlohmann::json& entry) {
        if (!entry.is_object()) return false;
        if (entry.value("document_id", std::uint64_t{0}) == identity.document_id)
            return true;
        return !identity.canonical_path.empty() &&
            canonical_path(entry.value("path", std::string{})) == identity.canonical_path;
    });
    std::string current;
    std::string previous;
    if (found != entries.end()) {
        const auto retained_revision = found->value("revision", std::uint64_t{0});
        if (retained_revision > clean_revision)
            return {true, "A newer recovery revision was preserved.", false};
        current = found->value("current", std::string{});
        previous = found->value("previous", std::string{});
    } else if (entries.size() >= maximum_documents) {
        return {false, "The recovery manifest reached its document capacity."};
    }
    nlohmann::json tombstone = record_metadata_json(identity);
    tombstone["document_id"] = identity.document_id;
    tombstone["path"] = identity.canonical_path;
    tombstone["revision"] = clean_revision;
    tombstone["clean_revision"] = clean_revision;
    tombstone["current"] = "";
    tombstone["previous"] = "";
    if (found != entries.end())
        *found = std::move(tombstone);
    else
        entries.push_back(std::move(tombstone));
    const auto persisted = write_manifest(manifest);
    if (!persisted.succeeded)
        return persisted;
    const auto sealed_previous = atomic_exact_write(previous_manifest_path(), manifest.dump());
    if (!sealed_previous.succeeded)
        return {false, "The clean outcome could not be sealed in the last-good manifest: " +
            sealed_previous.detail};
    const auto directory = storage_directory();
    std::error_code ec;
    if (valid_journal_filename(current)) std::filesystem::remove(directory / current, ec);
    ec.clear();
    if (valid_journal_filename(previous)) std::filesystem::remove(directory / previous, ec);
    return {true, {}, true};
#endif
}

inline std::string encode_session(const session_state_t& state) {
    nlohmann::json document = {
        {"schema", "aida.programming-documents"},
        {"version", session_version},
        {"tabs", nlohmann::json::array()},
        {"groups", nlohmann::json::array()},
        {"active_document_id", state.active_document_id}
    };
    for (std::size_t index = 0; index < state.documents.size() && index < maximum_documents; ++index) {
        const auto& item = state.documents[index];
        document["tabs"].push_back({
            {"path", item.canonical_path}, {"filename", item.filename},
            {"document_id", item.document_id}, {"group_id", item.group_id},
            {"pinned", item.pinned}, {"caret_line", item.caret_line},
            {"caret_column", item.caret_column}, {"scroll_x", item.scroll_x},
            {"scroll_y", item.scroll_y}, {"revision", item.revision},
            {"content_hash", item.content_hash}, {"base_fingerprint", item.base_fingerprint},
            {"encoding", item.text.encoding}, {"bom", item.text.bom}, {"eol", item.text.eol},
            {"selection_anchor_line", item.selection_anchor_line},
            {"selection_anchor_column", item.selection_anchor_column},
            {"selection_active", item.selection_active},
            {"folded_lines", item.folded_lines}, {"language_override", item.language_override}
        });
    }
    for (const auto& source : state.groups) {
        nlohmann::json group = {{"group_id", source.group_id},
            {"active_document_id", source.active_document_id},
            {"back", nlohmann::json::array()}, {"forward", nlohmann::json::array()}};
        const auto append = [](nlohmann::json& target, const std::vector<navigation_record_t>& values) {
            for (std::size_t index = 0; index < values.size() && index < 128; ++index)
                target.push_back({{"document_id", values[index].document_id},
                    {"line", values[index].line}, {"column", values[index].column}});
        };
        append(group["back"], source.back);
        append(group["forward"], source.forward);
        document["groups"].push_back(std::move(group));
    }
    return document.dump();
}

inline operation_result_t decode_session(std::string_view raw, session_state_t& state) {
    state = {};
    if (raw.empty())
        return {true, {}};
    const auto document = nlohmann::json::parse(raw, nullptr, false);
    if (document.is_discarded())
        return {false, "Programming document session JSON is corrupt."};
    const nlohmann::json* tabs = document.is_array() ? &document : nullptr;
    unsigned version = 0;
    if (document.is_object()) {
        version = document.value("version", 0U);
        if (document.value("schema", std::string{}) != "aida.programming-documents" ||
            (version < 1 || version > session_version) ||
            !document.contains("tabs") || !document["tabs"].is_array())
            return {false, "Programming document session schema or version is unsupported."};
        tabs = &document["tabs"];
        state.active_document_id = document.value("active_document_id", std::uint64_t{0});
    }
    state.migrated_legacy = !document.is_object() || version < session_version;
    if (!tabs || tabs->size() > maximum_documents)
        return {false, "Programming document session exceeds its document capacity."};
    for (const auto& item : *tabs) {
        document_record_t record;
        if (item.is_string()) {
            record.original_path = item.get<std::string>();
            record.canonical_path = canonical_path(record.original_path);
            record.filename = std::filesystem::path(record.canonical_path).filename().string();
        } else if (item.is_object()) {
            record.original_path = item.value("path", std::string{});
            record.canonical_path = canonical_path(record.original_path);
            record.filename = item.value("filename", std::filesystem::path(record.canonical_path).filename().string());
            record.document_id = item.value("document_id", std::uint64_t{0});
            record.group_id = item.value("group_id", std::uint32_t{0});
            record.pinned = item.value("pinned", false);
            record.caret_line = (std::max)(item.value("caret_line", 0), 0);
            record.caret_column = (std::max)(item.value("caret_column", 0), 0);
            record.selection_anchor_line = (std::max)(
                item.value("selection_anchor_line", record.caret_line), 0);
            record.selection_anchor_column = (std::max)(
                item.value("selection_anchor_column", record.caret_column), 0);
            record.selection_active = item.value("selection_active", false);
            record.scroll_x = (std::max)(item.value("scroll_x", 0.f), 0.f);
            record.scroll_y = (std::max)(item.value("scroll_y", 0.f), 0.f);
            record.folded_lines = item.value("folded_lines", std::vector<int>{});
            record.language_override = item.value("language_override", std::string{});
            record.revision = (std::max)(item.value("revision", std::uint64_t{1}), std::uint64_t{1});
            record.content_hash = item.value("content_hash", std::uint64_t{0});
            record.base_fingerprint = item.value("base_fingerprint", std::uint64_t{0});
            record.text.encoding = item.value("encoding", std::string("utf-8"));
            record.text.bom = item.value("bom", std::string("none"));
            record.text.eol = item.value("eol", std::string("lf"));
        } else {
            continue;
        }
        if (record.filename.size() > 1024 || record.canonical_path.size() > 32768 ||
            record.original_path.size() > 32768 ||
            record.text.encoding.size() > 32 || record.text.bom.size() > 32 ||
            record.text.eol.size() > 16 || record.folded_lines.size() > 4096 ||
            record.language_override.size() > 64 ||
            std::any_of(record.folded_lines.begin(), record.folded_lines.end(),
                [](int line) { return line < 0; }))
            continue;
        if (!record.canonical_path.empty() || record.document_id != 0)
            state.documents.push_back(std::move(record));
    }
    if (document.is_object() && document.contains("groups") && document["groups"].is_array()) {
        if (document["groups"].size() > 256)
            return {false, "Programming document session exceeds its group capacity."};
        for (const auto& item : document["groups"]) {
            if (!item.is_object()) continue;
            group_record_t group;
            group.group_id = item.value("group_id", std::uint32_t{0});
            group.active_document_id = item.value("active_document_id", std::uint64_t{0});
            const auto read_history = [&](const char* name, std::vector<navigation_record_t>& output) {
                if (!item.contains(name) || !item[name].is_array()) return;
                for (const auto& value : item[name]) {
                    if (output.size() >= 128 || !value.is_object()) break;
                    navigation_record_t navigation;
                    navigation.document_id = value.value("document_id", std::uint64_t{0});
                    navigation.line = (std::max)(value.value("line", 0), 0);
                    navigation.column = (std::max)(value.value("column", 0), 0);
                    if (navigation.document_id != 0)
                        output.push_back(navigation);
                }
            };
            read_history("back", group.back);
            read_history("forward", group.forward);
            state.groups.push_back(std::move(group));
        }
    }
    return {true, state.migrated_legacy ? "A legacy programming session was migrated in memory." : std::string{}};
}

}
