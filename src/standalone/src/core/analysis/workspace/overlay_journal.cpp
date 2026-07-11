#include "overlay_journal.hpp"

#include "checked_range.hpp"

#include <sqlite3.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <charconv>
#include <array>
#include <chrono>
#include <cctype>
#include <cstring>
#include <future>
#include <limits>
#include <mutex>
#include <sstream>
#include <utility>

namespace aida::analysis {

namespace {

using json = nlohmann::json;

class overlay_statement_t final {
public:
    ~overlay_statement_t() {
        if (statement_)
            sqlite3_finalize(statement_);
    }

    workspace_result_t<void> prepare(sqlite3* database, const char* sql,
                                     const char* phase) {
        database_ = database;
        phase_ = phase;
        const int status = sqlite3_prepare_v3(database, sql, -1,
                                              SQLITE_PREPARE_PERSISTENT,
                                              &statement_, nullptr);
        if (status == SQLITE_OK)
            return workspace_result_t<void>::success();
        return workspace_result_t<void>::failure(error(status, "failed to prepare overlay statement"));
    }

    sqlite3_stmt* get() const noexcept { return statement_; }

    workspace_result_t<void> bind_int(int index, std::int64_t value) {
        return bind(sqlite3_bind_int64(statement_, index, value));
    }

    workspace_result_t<void> bind_uint(int index, std::uint64_t value) {
        std::int64_t encoded = 0;
        std::memcpy(&encoded, &value, sizeof(encoded));
        return bind_int(index, encoded);
    }

    workspace_result_t<void> bind_text(int index, const std::string& value) {
        if (value.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
            return workspace_result_t<void>::failure(error(SQLITE_TOOBIG, "overlay text exceeds SQLite limit"));
        return bind(sqlite3_bind_text(statement_, index, value.data(),
                                      static_cast<int>(value.size()), SQLITE_TRANSIENT));
    }

    workspace_result_t<void> bind_null(int index) {
        return bind(sqlite3_bind_null(statement_, index));
    }

    workspace_result_t<void> step_done() {
        const int status = sqlite3_step(statement_);
        if (status == SQLITE_DONE)
            return workspace_result_t<void>::success();
        return workspace_result_t<void>::failure(error(status, "overlay statement did not complete"));
    }

    workspace_result_t<void> reset() {
        int status = sqlite3_reset(statement_);
        if (status == SQLITE_OK)
            status = sqlite3_clear_bindings(statement_);
        return bind(status);
    }

private:
    workspace_error_t error(int status, std::string message) const {
        auto result = make_workspace_error(workspace_error_code_t::persistence_failure,
                                           std::move(message), phase_);
        result.sqlite_status = status;
        if (database_) {
            result.details.emplace_back("sqlite_extended_status",
                                        std::to_string(sqlite3_extended_errcode(database_)));
            const char* detail = sqlite3_errmsg(database_);
            if (detail && *detail)
                result.details.emplace_back("sqlite_message", detail);
        }
        return result;
    }

    workspace_result_t<void> bind(int status) {
        if (status == SQLITE_OK)
            return workspace_result_t<void>::success();
        return workspace_result_t<void>::failure(error(status, "overlay statement binding failed"));
    }

    sqlite3* database_ = nullptr;
    sqlite3_stmt* statement_ = nullptr;
    const char* phase_ = "overlay_journal";
};

workspace_result_t<void> overlay_exec(sqlite3* database, const char* sql,
                                     const char* phase) {
    char* detail = nullptr;
    const int status = sqlite3_exec(database, sql, nullptr, nullptr, &detail);
    if (status == SQLITE_OK)
        return workspace_result_t<void>::success();
    auto error = make_workspace_error(workspace_error_code_t::persistence_failure,
                                      detail && *detail ? detail : "overlay SQL failed", phase);
    error.sqlite_status = status;
    sqlite3_free(detail);
    return workspace_result_t<void>::failure(std::move(error));
}

std::uint64_t overlay_utc_ms() noexcept {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

json address_json(const address_t& address) {
    return json{{"architecture", static_cast<unsigned>(address.architecture)},
                {"mode", static_cast<unsigned>(address.mode)},
                {"space", static_cast<unsigned>(address.space)},
                {"value", std::to_string(address.value)}};
}

workspace_result_t<address_t> parse_address(const json& value) {
    if (!value.is_object() || !value.contains("space") || !value.contains("value") ||
        !value.contains("architecture") || !value.contains("mode") ||
        !value["space"].is_number_unsigned() || !value["value"].is_string() ||
        !value["architecture"].is_number_unsigned() || !value["mode"].is_number_unsigned()) {
        return workspace_result_t<address_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "overlay address payload is malformed", "overlay_journal.recovery"));
    }
    address_t result;
    try {
        result.space = static_cast<address_space_id_t>(value["space"].get<unsigned>());
        const std::string address_value = value["value"].get<std::string>();
        const auto parsed = std::from_chars(address_value.data(),
            address_value.data() + address_value.size(), result.value, 10);
        if (parsed.ec != std::errc{} || parsed.ptr != address_value.data() + address_value.size())
            throw std::invalid_argument("invalid address");
        result.architecture = static_cast<architecture_id_t>(value["architecture"].get<unsigned>());
        result.mode = static_cast<architecture_mode_t>(value["mode"].get<unsigned>());
    } catch (...) {
        return workspace_result_t<address_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "overlay address value is invalid", "overlay_journal.recovery"));
    }
    return workspace_result_t<address_t>::success(result);
}

std::string hex_encode(const std::vector<std::uint8_t>& bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.resize(bytes.size() * 2);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        result[index * 2] = digits[bytes[index] >> 4];
        result[index * 2 + 1] = digits[bytes[index] & 15];
    }
    return result;
}

workspace_result_t<std::vector<std::uint8_t>> hex_decode(const std::string& text) {
    if ((text.size() & 1U) != 0) {
        return workspace_result_t<std::vector<std::uint8_t>>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "overlay byte payload has odd-length hexadecimal data",
            "overlay_journal.recovery"));
    }
    auto value = [](char character) -> int {
        if (character >= '0' && character <= '9') return character - '0';
        if (character >= 'a' && character <= 'f') return character - 'a' + 10;
        if (character >= 'A' && character <= 'F') return character - 'A' + 10;
        return -1;
    };
    std::vector<std::uint8_t> result(text.size() / 2);
    for (std::size_t index = 0; index < result.size(); ++index) {
        const int high = value(text[index * 2]);
        const int low = value(text[index * 2 + 1]);
        if (high < 0 || low < 0) {
            return workspace_result_t<std::vector<std::uint8_t>>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "overlay byte payload contains non-hexadecimal data",
                "overlay_journal.recovery"));
        }
        result[index] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return workspace_result_t<std::vector<std::uint8_t>>::success(std::move(result));
}

json operation_json(const overlay_operation_t& operation) {
    json result{{"address", address_json(operation.address)},
                {"assembly", operation.assembly},
                {"bytes", hex_encode(operation.bytes)},
                {"integer_type", operation.integer_type},
                {"integer_value", operation.integer_value},
                {"kind", static_cast<unsigned>(operation.kind)},
                {"name", operation.name},
                {"signature", operation.signature},
                {"stack_offset", std::to_string(operation.stack_offset)},
                {"text", operation.text},
                {"type", operation.type},
                {"variable", operation.variable}};
    result["end"] = operation.end ? address_json(*operation.end) : json(nullptr);
    return result;
}

workspace_result_t<overlay_operation_t> parse_operation(const std::string& text) {
    auto value = json::parse(text, nullptr, false);
    if (value.is_discarded() || !value.is_object()) {
        return workspace_result_t<overlay_operation_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "overlay operation JSON is malformed", "overlay_journal.recovery"));
    }
    const std::array<const char*, 12> fields{{"address", "assembly", "bytes", "integer_type",
        "integer_value", "kind", "name", "signature", "stack_offset", "text", "type", "variable"}};
    for (const char* field : fields) {
        if (!value.contains(field)) {
            return workspace_result_t<overlay_operation_t>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "overlay operation JSON is missing a required field",
                "overlay_journal.recovery"));
        }
    }
    overlay_operation_t operation;
    auto address = parse_address(value["address"]);
    if (!address) return workspace_result_t<overlay_operation_t>::failure(address.error());
    operation.address = address.take_value();
    if (value.contains("end") && !value["end"].is_null()) {
        auto end = parse_address(value["end"]);
        if (!end) return workspace_result_t<overlay_operation_t>::failure(end.error());
        operation.end = end.take_value();
    }
    try {
        operation.kind = static_cast<overlay_operation_kind_t>(value["kind"].get<unsigned>());
        operation.assembly = value["assembly"].get<std::string>();
        operation.integer_type = value["integer_type"].get<std::string>();
        operation.integer_value = value["integer_value"].get<std::string>();
        operation.name = value["name"].get<std::string>();
        operation.signature = value["signature"].get<std::string>();
        const std::string stack_offset = value["stack_offset"].get<std::string>();
        const auto parsed_stack = std::from_chars(stack_offset.data(),
            stack_offset.data() + stack_offset.size(), operation.stack_offset, 10);
        if (parsed_stack.ec != std::errc{} ||
            parsed_stack.ptr != stack_offset.data() + stack_offset.size())
            throw std::invalid_argument("invalid stack offset");
        operation.text = value["text"].get<std::string>();
        operation.type = value["type"].get<std::string>();
        operation.variable = value["variable"].get<std::string>();
        auto bytes = hex_decode(value["bytes"].get<std::string>());
        if (!bytes) return workspace_result_t<overlay_operation_t>::failure(bytes.error());
        operation.bytes = bytes.take_value();
    } catch (...) {
        return workspace_result_t<overlay_operation_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "overlay operation JSON contains an invalid value",
            "overlay_journal.recovery"));
    }
    return workspace_result_t<overlay_operation_t>::success(std::move(operation));
}

std::string address_key(const address_t& address) {
    return std::to_string(static_cast<unsigned>(address.space)) + ":" +
           std::to_string(address.value) + ":" +
           std::to_string(static_cast<unsigned>(address.architecture)) + ":" +
           std::to_string(static_cast<unsigned>(address.mode));
}

std::string entity_key(const overlay_operation_t& operation) {
    std::string prefix;
    switch (operation.kind) {
    case overlay_operation_kind_t::comment: prefix = "comment"; break;
    case overlay_operation_kind_t::name: prefix = "name"; break;
    case overlay_operation_kind_t::bookmark: prefix = "bookmark"; break;
    case overlay_operation_kind_t::type_declaration: return "type_declaration:" + operation.name;
    case overlay_operation_kind_t::define_function: prefix = "define_function"; break;
    case overlay_operation_kind_t::define_code: prefix = "define_code"; break;
    case overlay_operation_kind_t::define_data: prefix = "define_data"; break;
    case overlay_operation_kind_t::undefine: prefix = "undefine"; break;
    case overlay_operation_kind_t::stack_variable:
    case overlay_operation_kind_t::delete_stack_variable:
        return "stack_variable:" + address_key(operation.address) + ":" +
               std::to_string(operation.stack_offset) + ":" + operation.name;
    case overlay_operation_kind_t::type_application:
        return "type_application:" + address_key(operation.address) + ":" +
               operation.variable + ":" + operation.name;
    case overlay_operation_kind_t::byte_patch:
    case overlay_operation_kind_t::assembly_patch:
    case overlay_operation_kind_t::integer_patch:
        prefix = "patch";
        break;
    }
    return prefix + ":" + address_key(operation.address);
}

bool removes_value(const overlay_operation_t& operation) {
    if (operation.kind == overlay_operation_kind_t::comment)
        return operation.text.empty();
    if (operation.kind == overlay_operation_kind_t::name ||
        operation.kind == overlay_operation_kind_t::bookmark)
        return operation.name.empty();
    return false;
}

bool contains_nul(const std::string& value) {
    return value.find('\0') != std::string::npos;
}

bool valid_integer_type(const std::string& value, std::size_t& byte_size) {
    static const std::pair<const char*, std::size_t> values[] = {
        {"i8", 1}, {"u8", 1}, {"i8le", 1}, {"u8le", 1},
        {"i8be", 1}, {"u8be", 1}, {"i16", 2}, {"u16", 2},
        {"i16le", 2}, {"u16le", 2}, {"i16be", 2}, {"u16be", 2},
        {"i32", 4}, {"u32", 4}, {"i32le", 4}, {"u32le", 4},
        {"i32be", 4}, {"u32be", 4}, {"i64", 8}, {"u64", 8},
        {"i64le", 8}, {"u64le", 8}, {"i64be", 8}, {"u64be", 8}
    };
    for (const auto& item : values) {
        if (value == item.first) {
            byte_size = item.second;
            return true;
        }
    }
    return false;
}

bool integer_patch_matches_value(const overlay_operation_t& operation,
                                 std::size_t byte_size) {
    const std::string& text = operation.integer_value;
    if (text.empty())
        return false;
    std::size_t cursor = 0;
    bool negative = false;
    if (text[cursor] == '+' || text[cursor] == '-') {
        negative = text[cursor] == '-';
        ++cursor;
    }
    int base = 10;
    if (cursor + 2 <= text.size() && text[cursor] == '0') {
        const char prefix = text[cursor + 1];
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
    if (cursor == text.size())
        return false;
    std::uint64_t magnitude = 0;
    const auto parsed = std::from_chars(text.data() + cursor,
                                        text.data() + text.size(),
                                        magnitude, base);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size())
        return false;
    const bool signed_type = !operation.integer_type.empty() &&
                             operation.integer_type.front() == 'i';
    if (negative && !signed_type)
        return false;
    const unsigned bits = static_cast<unsigned>(byte_size * 8);
    const std::uint64_t mask = bits == 64
        ? (std::numeric_limits<std::uint64_t>::max)()
        : (std::uint64_t{1} << bits) - 1;
    std::uint64_t encoded = magnitude;
    if (signed_type) {
        const std::uint64_t sign_limit = std::uint64_t{1} << (bits - 1);
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
    const bool big_endian = operation.integer_type.size() >= 2 &&
        operation.integer_type.compare(operation.integer_type.size() - 2, 2, "be") == 0;
    for (std::size_t index = 0; index < byte_size; ++index) {
        const unsigned shift = static_cast<unsigned>((big_endian
            ? byte_size - index - 1 : index) * 8);
        if (operation.bytes[index] != static_cast<std::uint8_t>(encoded >> shift))
            return false;
    }
    return true;
}

workspace_result_t<std::uint64_t> patch_provider_offset(
    const overlay_operation_t& operation,
    const analysis_workspace_t& workspace) {
    const auto size = static_cast<std::uint64_t>(operation.bytes.size());
    if (workspace.target_kind() == target_kind_t::static_file) {
        auto image = workspace.image();
        if (operation.address.space == address_space_id_t::file_offset)
            return workspace_result_t<std::uint64_t>::success(operation.address.value);
        if (image && operation.address.space == address_space_id_t::relative_virtual)
            return image->rva_to_file_offset(operation.address.value, size);
        if (image && operation.address.space == address_space_id_t::virtual_address) {
            auto rva = image->va_to_rva(operation.address.value);
            if (!rva)
                return workspace_result_t<std::uint64_t>::failure(rva.error());
            return image->rva_to_file_offset(rva.value(), size);
        }
    } else if (operation.address.space == address_space_id_t::live_virtual) {
        const std::uint64_t base = workspace.identity().module()
            ? workspace.identity().module()->base : workspace.identity().image_base();
        if (operation.address.value >= base)
            return workspace_result_t<std::uint64_t>::success(operation.address.value - base);
    }
    return workspace_result_t<std::uint64_t>::failure(make_workspace_error(
        workspace_error_code_t::unsupported_address_space,
        "patch address space cannot map to provider bytes",
        "overlay_journal.validate"));
}

workspace_result_t<void> validate_workspace_address(
    const address_t& address,
    const analysis_workspace_t& workspace,
    const char* phase) {
    const auto expected_mode = workspace.identity().architecture() == architecture_id_t::x86
        ? architecture_mode_t::x86_32
        : (workspace.identity().architecture() == architecture_id_t::x86_64
            ? architecture_mode_t::x86_64 : architecture_mode_t::unknown);
    if (address.architecture != workspace.identity().architecture() ||
        address.mode == architecture_mode_t::unknown || address.mode != expected_mode ||
        static_cast<unsigned>(address.space) >
            static_cast<unsigned>(address_space_id_t::live_virtual)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "overlay address identity does not match the workspace",
            phase));
    }
    if (workspace.target_kind() == target_kind_t::live_snapshot) {
        if (address.space != address_space_id_t::live_virtual) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::unsupported_address_space,
                "live overlay addresses must use the live-virtual address space",
                phase));
        }
        const std::uint64_t base = workspace.identity().module()
            ? workspace.identity().module()->base : workspace.identity().image_base();
        if (address.value < base || address.value - base >= workspace.provider().size()) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::out_of_range,
                "live overlay address is outside the captured snapshot",
                phase));
        }
        return workspace_result_t<void>::success();
    }
    if (address.space == address_space_id_t::live_virtual) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::unsupported_address_space,
            "static overlays cannot use the live-virtual address space",
            phase));
    }
    auto image = workspace.image();
    if (address.space == address_space_id_t::file_offset) {
        if (address.value >= workspace.provider().size()) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::out_of_range,
                "overlay file offset is outside the provider",
                phase));
        }
        return workspace_result_t<void>::success();
    }
    if (!image) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::provider_unavailable,
            "static virtual overlay address requires a parsed image",
            phase));
    }
    std::uint64_t rva = address.value;
    if (address.space == address_space_id_t::virtual_address) {
        auto translated = image->va_to_rva(address.value);
        if (!translated)
            return workspace_result_t<void>::failure(translated.error());
        rva = translated.value();
    }
    if (rva >= image->image_size()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::out_of_range,
            "overlay virtual address is outside the image",
            phase));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> validate_operation(
    const overlay_operation_t& operation, const overlay_limits_t& limits,
    const analysis_workspace_t& workspace, std::size_t& total_patch_bytes) {
    const unsigned kind_value = static_cast<unsigned>(operation.kind);
    if (kind_value > static_cast<unsigned>(overlay_operation_kind_t::integer_patch)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "overlay operation kind is invalid", "overlay_journal.validate"));
    }
    if (contains_nul(operation.name) || contains_nul(operation.text) ||
        contains_nul(operation.type) || contains_nul(operation.variable) ||
        contains_nul(operation.signature) || contains_nul(operation.assembly) ||
        contains_nul(operation.integer_type) || contains_nul(operation.integer_value)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "overlay text fields may not contain NUL bytes", "overlay_journal.validate"));
    }
    if (operation.name.size() > limits.max_name_bytes ||
        operation.variable.size() > limits.max_name_bytes) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "overlay name exceeds configured limit", "overlay_journal.validate"));
    }
    if (operation.type.size() > limits.max_type_bytes ||
        operation.signature.size() > limits.max_type_bytes ||
        operation.text.size() > limits.max_comment_bytes) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "overlay text exceeds configured limit", "overlay_journal.validate"));
    }
    if (operation.kind != overlay_operation_kind_t::type_declaration) {
        auto address_result = validate_workspace_address(
            operation.address, workspace, "overlay_journal.validate");
        if (!address_result)
            return address_result;
    }
    if (operation.end) {
        if (operation.end->space != operation.address.space ||
            operation.end->architecture != operation.address.architecture ||
            operation.end->mode != operation.address.mode ||
            operation.end->value <= operation.address.value) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::invalid_argument,
                "overlay end address is not a valid increasing range",
                "overlay_journal.validate"));
        }
        auto inclusive_end = *operation.end;
        --inclusive_end.value;
        auto end_result = validate_workspace_address(
            inclusive_end, workspace, "overlay_journal.validate");
        if (!end_result)
            return end_result;
    }
    if (operation.kind == overlay_operation_kind_t::type_declaration &&
        (operation.name.empty() || operation.type.empty())) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "type declaration requires a name and declaration text",
            "overlay_journal.validate"));
    }
    if ((operation.kind == overlay_operation_kind_t::stack_variable ||
         operation.kind == overlay_operation_kind_t::delete_stack_variable) &&
        operation.name.empty()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "stack variable operation requires a name", "overlay_journal.validate"));
    }
    if (operation.kind == overlay_operation_kind_t::stack_variable && operation.type.empty()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "stack variable declaration requires a type", "overlay_journal.validate"));
    }
    const bool patch = operation.kind == overlay_operation_kind_t::byte_patch ||
                       operation.kind == overlay_operation_kind_t::assembly_patch ||
                       operation.kind == overlay_operation_kind_t::integer_patch;
    if (patch) {
        if (operation.bytes.empty()) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::invalid_argument,
                "patch operation requires encoded bytes", "overlay_journal.validate"));
        }
        if (operation.bytes.size() > limits.max_patch_bytes_per_item ||
            operation.bytes.size() > limits.max_patch_bytes_per_transaction - total_patch_bytes) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "patch operation exceeds byte limits", "overlay_journal.validate"));
        }
        total_patch_bytes += operation.bytes.size();
        if (operation.kind == overlay_operation_kind_t::assembly_patch) {
            if (operation.assembly.empty() || operation.assembly.size() > limits.max_assembly_bytes) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::limit_exceeded,
                    "assembly patch text is empty or exceeds its limit",
                    "overlay_journal.validate"));
            }
            const std::size_t statements = 1 + static_cast<std::size_t>(std::count_if(
                operation.assembly.begin(), operation.assembly.end(),
                [](char character) { return character == ';' || character == '\n'; }));
            if (statements > limits.max_assembly_statements) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::limit_exceeded,
                    "assembly patch exceeds statement limit", "overlay_journal.validate"));
            }
        }
        if (operation.kind == overlay_operation_kind_t::integer_patch) {
            std::size_t encoded_size = 0;
            if (operation.integer_value.empty() ||
                !valid_integer_type(operation.integer_type, encoded_size) ||
                operation.bytes.size() != encoded_size ||
                !integer_patch_matches_value(operation, encoded_size)) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::invalid_argument,
                    "integer patch type, value, width, or encoding is invalid",
                    "overlay_journal.validate"));
            }
        }
        auto offset = patch_provider_offset(operation, workspace);
        if (!offset) return workspace_result_t<void>::failure(offset.error());
        auto span = validate_span(offset.value(), operation.bytes.size(), workspace.provider().size(),
                                  "overlay_journal.validate");
        if (!span) return workspace_result_t<void>::failure(span.error());
    }
    try {
        (void)operation_json(operation).dump();
    } catch (...) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "overlay fields are not valid UTF-8", "overlay_journal.validate"));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> bind_operation_address(overlay_statement_t& statement, int first,
                                                const address_t& address) {
    auto result = statement.bind_int(first, static_cast<std::int64_t>(address.space));
    if (!result) return result;
    result = statement.bind_uint(first + 1, address.value); if (!result) return result;
    result = statement.bind_int(first + 2, static_cast<std::int64_t>(address.architecture)); if (!result) return result;
    return statement.bind_int(first + 3, static_cast<std::int64_t>(address.mode));
}

std::string overlay_column_text(sqlite3_stmt* statement, int column) {
    const auto* text = sqlite3_column_text(statement, column);
    const int bytes = sqlite3_column_bytes(statement, column);
    if (!text || bytes <= 0)
        return {};
    return std::string(reinterpret_cast<const char*>(text), static_cast<std::size_t>(bytes));
}

json transaction_result_json(const overlay_transaction_result_t& result) {
    json operations = json::array();
    for (const auto& operation : result.operations) {
        operations.push_back(json{{"entity_key", operation.entity_key},
                                  {"index", operation.index},
                                  {"removes_value", operation.removes_value}});
    }
    return json{{"committed", result.committed},
                {"dry_run", result.dry_run},
                {"idempotent_replay", result.idempotent_replay},
                {"operations", std::move(operations)},
                {"revision", std::to_string(result.revision)},
                {"transaction_id", std::to_string(result.transaction_id)}};
}

workspace_result_t<overlay_transaction_result_t> parse_transaction_result(
    const std::string& text) {
    auto value = json::parse(text, nullptr, false);
    if (value.is_discarded() || !value.is_object()) {
        return workspace_result_t<overlay_transaction_result_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "idempotency result payload is malformed", "overlay_journal.recovery"));
    }
    overlay_transaction_result_t result;
    try {
        const std::string transaction_id = value.at("transaction_id").get<std::string>();
        const std::string revision = value.at("revision").get<std::string>();
        const auto parsed_transaction = std::from_chars(transaction_id.data(),
            transaction_id.data() + transaction_id.size(), result.transaction_id, 10);
        const auto parsed_revision = std::from_chars(revision.data(),
            revision.data() + revision.size(), result.revision, 10);
        if (parsed_transaction.ec != std::errc{} ||
            parsed_transaction.ptr != transaction_id.data() + transaction_id.size() ||
            parsed_revision.ec != std::errc{} ||
            parsed_revision.ptr != revision.data() + revision.size())
            throw std::invalid_argument("invalid transaction result identifier");
        result.committed = value.at("committed").get<bool>();
        result.dry_run = value.at("dry_run").get<bool>();
        result.idempotent_replay = value.at("idempotent_replay").get<bool>();
        for (const auto& item : value.at("operations")) {
            overlay_operation_result_t operation;
            operation.index = item.at("index").get<std::size_t>();
            operation.entity_key = item.at("entity_key").get<std::string>();
            operation.removes_value = item.at("removes_value").get<bool>();
            result.operations.push_back(std::move(operation));
        }
    } catch (...) {
        return workspace_result_t<overlay_transaction_result_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "idempotency result payload has invalid fields", "overlay_journal.recovery"));
    }
    return workspace_result_t<overlay_transaction_result_t>::success(std::move(result));
}

workspace_result_t<void> wait_ticket(const persistence_ticket_t& ticket,
                                     const cancellation_token_t& cancel) {
    if (!ticket.completion.valid()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::persistence_failure,
            "persistence queue returned an invalid completion ticket",
            "overlay_journal"));
    }
    for (;;) {
        if (ticket.completion.wait_for(std::chrono::milliseconds(10)) == std::future_status::ready) {
            const auto& result = ticket.completion.get();
            if (result)
                return workspace_result_t<void>::success();
            return workspace_result_t<void>::failure(result.error());
        }
        if (cancel.stop_requested())
            continue;
    }
}

workspace_result_t<void> apply_item(sqlite3* database, const std::string& entity,
                                    overlay_operation_kind_t kind,
                                    const address_t& address,
                                    const std::string& payload,
                                    std::uint64_t revision) {
    auto parsed = json::parse(payload, nullptr, false);
    if (parsed.is_discarded()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "overlay payload cannot be parsed", "overlay_journal.apply"));
    }
    if (parsed.is_null()) {
        overlay_statement_t remove;
        auto result = remove.prepare(database,
            "DELETE FROM overlay_items WHERE entity_key=?1", "overlay_journal.apply");
        if (!result) return result;
        result = remove.bind_text(1, entity); if (!result) return result;
        return remove.step_done();
    }
    overlay_statement_t upsert;
    auto result = upsert.prepare(database,
        "INSERT INTO overlay_items(entity_key,kind,address_space,address_value,address_arch,address_mode,payload_json,updated_revision) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(entity_key) DO UPDATE SET kind=excluded.kind,address_space=excluded.address_space,address_value=excluded.address_value,address_arch=excluded.address_arch,address_mode=excluded.address_mode,payload_json=excluded.payload_json,updated_revision=excluded.updated_revision",
        "overlay_journal.apply");
    if (!result) return result;
    result = upsert.bind_text(1, entity); if (!result) return result;
    result = upsert.bind_int(2, static_cast<std::int64_t>(kind)); if (!result) return result;
    result = bind_operation_address(upsert, 3, address); if (!result) return result;
    result = upsert.bind_text(7, payload); if (!result) return result;
    result = upsert.bind_uint(8, revision); if (!result) return result;
    return upsert.step_done();
}

struct overlay_db_state_t {
    std::uint64_t revision = 0;
    std::uint64_t cursor = 0;
    std::uint64_t next_transaction = 1;
    std::uint64_t epoch = 1;
};

workspace_result_t<overlay_db_state_t> read_overlay_state(sqlite3* database,
                                                          const char* phase) {
    overlay_statement_t statement;
    auto result = statement.prepare(database,
        "SELECT revision,history_cursor,next_transaction_id,history_epoch FROM overlay_state WHERE singleton=1",
        phase);
    if (!result) return workspace_result_t<overlay_db_state_t>::failure(result.error());
    const int status = sqlite3_step(statement.get());
    if (status != SQLITE_ROW) {
        auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                          "overlay state row is missing", phase);
        error.sqlite_status = status;
        return workspace_result_t<overlay_db_state_t>::failure(std::move(error));
    }
    const auto revision = sqlite3_column_int64(statement.get(), 0);
    const auto cursor = sqlite3_column_int64(statement.get(), 1);
    const auto next_transaction = sqlite3_column_int64(statement.get(), 2);
    const auto epoch = sqlite3_column_int64(statement.get(), 3);
    if (revision < 0 || cursor < 0 || next_transaction <= 0 || epoch <= 0 ||
        cursor >= next_transaction) {
        auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                          "overlay state values are invalid", phase);
        error.sqlite_status = SQLITE_CORRUPT;
        return workspace_result_t<overlay_db_state_t>::failure(std::move(error));
    }
    overlay_db_state_t state;
    state.revision = static_cast<std::uint64_t>(revision);
    state.cursor = static_cast<std::uint64_t>(cursor);
    state.next_transaction = static_cast<std::uint64_t>(next_transaction);
    state.epoch = static_cast<std::uint64_t>(epoch);
    return workspace_result_t<overlay_db_state_t>::success(state);
}

}

overlay_journal_t::overlay_journal_t(std::shared_ptr<analysis_workspace_t> workspace,
                                     std::shared_ptr<workspace_database_t> database,
                                     overlay_limits_t limits)
    : workspace_(std::move(workspace)), database_(std::move(database)), limits_(limits) {
}

overlay_journal_t::~overlay_journal_t() {
    request_cancel();
}

workspace_result_t<std::shared_ptr<overlay_journal_t>> overlay_journal_t::open(
    std::shared_ptr<analysis_workspace_t> workspace,
    std::shared_ptr<workspace_database_t> database,
    overlay_limits_t limits) {
    if (!workspace || !database || limits.max_operations == 0 ||
        limits.max_patch_bytes_per_item == 0 ||
        limits.max_patch_bytes_per_transaction < limits.max_patch_bytes_per_item) {
        return workspace_result_t<std::shared_ptr<overlay_journal_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "overlay journal requires a workspace, database, and valid limits",
                                 "overlay_journal.open"));
    }
    if (!database->options().identity ||
        database->options().identity->binary_id() != workspace->identity().binary_id()) {
        return workspace_result_t<std::shared_ptr<overlay_journal_t>>::failure(
            make_workspace_error(workspace_error_code_t::target_conflict,
                                 "overlay database identity does not match the workspace",
                                 "overlay_journal.open"));
    }
    auto journal = std::shared_ptr<overlay_journal_t>(
        new overlay_journal_t(std::move(workspace), std::move(database), limits));
    auto recovered = journal->recover_and_load(journal->cancellation_.token());
    if (!recovered)
        return workspace_result_t<std::shared_ptr<overlay_journal_t>>::failure(recovered.error());
    auto owner = journal->workspace_.lock();
    if (!owner) {
        return workspace_result_t<std::shared_ptr<overlay_journal_t>>::failure(
            make_workspace_error(workspace_error_code_t::target_not_found,
                                 "overlay workspace closed during recovery",
                                 "overlay_journal.open"));
    }
    auto attach_failure = [&journal](workspace_error_t error) {
        journal->request_cancel();
        auto drained = journal->drain(
            std::chrono::steady_clock::now() + std::chrono::seconds(2));
        if (!drained) {
            error.details.emplace_back("attach_cleanup_code",
                                       drained.error().stable_code());
            error.details.emplace_back("attach_cleanup_message",
                                       drained.error().message);
        }
        return workspace_result_t<std::shared_ptr<overlay_journal_t>>::failure(
            std::move(error));
    };
    const auto current_revision = owner->overlay_revision();
    if (journal->revision_ < current_revision) {
        return workspace_result_t<std::shared_ptr<overlay_journal_t>>::failure(
            make_workspace_error(workspace_error_code_t::revision_conflict,
                                 "persisted overlay revision precedes the workspace revision",
                                 "overlay_journal.open"));
    }
    auto registered = owner->register_lifecycle_participant(journal);
    if (!registered)
        return attach_failure(registered.error());
    if (journal->revision_ > current_revision) {
        const auto restored = owner->restore_overlay_revision(current_revision,
                                                              journal->revision_);
        if (!restored)
            return attach_failure(restored.error());
    }
    auto installed = owner->install_overlay(journal);
    if (!installed)
        return attach_failure(installed.error());
    return workspace_result_t<std::shared_ptr<overlay_journal_t>>::success(std::move(journal));
}

workspace_result_t<void> overlay_journal_t::recover_and_load(
    const cancellation_token_t& cancel) {
    auto integrity = database_->with_reader([](sqlite3* reader) {
        overlay_statement_t statement;
        auto prepared = statement.prepare(reader, "PRAGMA quick_check(1)",
                                          "overlay_journal.recovery");
        if (!prepared) return prepared;
        const int status = sqlite3_step(statement.get());
        if (status != SQLITE_ROW || overlay_column_text(statement.get(), 0) != "ok") {
            auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                              "workspace database quick check failed",
                                              "overlay_journal.recovery");
            error.sqlite_status = status;
            return workspace_result_t<void>::failure(std::move(error));
        }
        return workspace_result_t<void>::success();
    });
    if (!integrity) return integrity;
    auto database = database_;
    auto ticket = database_->enqueue_write("analysis.overlay.recover",
        [](sqlite3* writer, const cancellation_token_t& token) {
            if (token.stop_requested()) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::cancelled,
                    "overlay recovery cancelled", "overlay_journal.recovery"));
            }
            auto begin = overlay_exec(writer, "BEGIN IMMEDIATE", "overlay_journal.recovery");
            if (!begin) return begin;
            auto cleared = overlay_exec(writer, "DELETE FROM overlay_items",
                                        "overlay_journal.recovery");
            if (!cleared) { overlay_exec(writer, "ROLLBACK", "overlay_journal.recovery"); return cleared; }
            overlay_statement_t statement;
            auto result = statement.prepare(writer,
                "SELECT o.entity_key,o.kind,o.address_space,o.address_value,o.address_arch,o.address_mode,o.after_json,t.revision FROM overlay_operations o JOIN overlay_transactions t ON t.transaction_id=o.transaction_id WHERE t.applied=1 AND t.abandoned=0 ORDER BY t.transaction_id,o.operation_index",
                "overlay_journal.recovery");
            if (!result) { overlay_exec(writer, "ROLLBACK", "overlay_journal.recovery"); return result; }
            for (;;) {
                const int status = sqlite3_step(statement.get());
                if (status == SQLITE_DONE)
                    break;
                if (status != SQLITE_ROW) {
                    overlay_exec(writer, "ROLLBACK", "overlay_journal.recovery");
                    auto error = make_workspace_error(workspace_error_code_t::persistence_failure,
                                                      "unable to replay overlay journal",
                                                      "overlay_journal.recovery");
                    error.sqlite_status = status;
                    return workspace_result_t<void>::failure(std::move(error));
                }
                address_t address;
                address.space = static_cast<address_space_id_t>(sqlite3_column_int(statement.get(), 2));
                address.value = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 3));
                address.architecture = static_cast<architecture_id_t>(sqlite3_column_int(statement.get(), 4));
                address.mode = static_cast<architecture_mode_t>(sqlite3_column_int(statement.get(), 5));
                result = apply_item(writer, overlay_column_text(statement.get(), 0),
                                    static_cast<overlay_operation_kind_t>(sqlite3_column_int(statement.get(), 1)),
                                    address, overlay_column_text(statement.get(), 6),
                                    static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 7)));
                if (!result) { overlay_exec(writer, "ROLLBACK", "overlay_journal.recovery"); return result; }
            }
            auto committed = overlay_exec(writer, "COMMIT", "overlay_journal.recovery");
            if (!committed) {
                overlay_exec(writer, "ROLLBACK", "overlay_journal.recovery");
                return committed;
            }
            return workspace_result_t<void>::success();
        }, cancel);
    auto waited = wait_ticket(ticket, cancel);
    if (!waited) return waited;
    return reload_items();
}

workspace_result_t<void> overlay_journal_t::reload_items() {
    std::unordered_map<std::string, overlay_operation_t> items;
    overlay_db_state_t state;
    auto result = database_->with_reader([&](sqlite3* reader) -> workspace_result_t<void> {
        auto state_result = read_overlay_state(reader, "overlay_journal.load");
        if (!state_result) return workspace_result_t<void>::failure(state_result.error());
        state = state_result.take_value();
        overlay_statement_t statement;
        auto prepared = statement.prepare(reader,
            "SELECT entity_key,payload_json FROM overlay_items ORDER BY entity_key",
            "overlay_journal.load");
        if (!prepared) return prepared;
        for (;;) {
            const int status = sqlite3_step(statement.get());
            if (status == SQLITE_DONE)
                break;
            if (status != SQLITE_ROW) {
                auto error = make_workspace_error(workspace_error_code_t::persistence_failure,
                                                  "unable to load overlay items",
                                                  "overlay_journal.load");
                error.sqlite_status = status;
                return workspace_result_t<void>::failure(std::move(error));
            }
            const std::string key = overlay_column_text(statement.get(), 0);
            auto operation = parse_operation(overlay_column_text(statement.get(), 1));
            if (!operation) return workspace_result_t<void>::failure(operation.error());
            auto owner = workspace_.lock();
            if (!owner) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::target_not_found,
                    "overlay workspace closed while loading journal items",
                    "overlay_journal.load"));
            }
            std::size_t patch_bytes = 0;
            auto validated = validate_operation(operation.value(), limits_, *owner,
                                                patch_bytes);
            if (!validated)
                return validated;
            if (key != entity_key(operation.value()) ||
                items.find(key) != items.end()) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "overlay materialized key does not match its payload",
                    "overlay_journal.load"));
            }
            items.emplace(key, operation.take_value());
        }
        return workspace_result_t<void>::success();
    });
    if (!result) return result;
    auto owner = workspace_.lock();
    if (!owner) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::target_not_found,
            "overlay workspace closed after loading journal items",
            "overlay_journal.load"));
    }
    std::vector<std::pair<std::uint64_t, std::uint64_t>> patch_ranges;
    for (const auto& item : items) {
        if (item.second.bytes.empty())
            continue;
        auto offset = patch_provider_offset(item.second, *owner);
        if (!offset)
            return workspace_result_t<void>::failure(offset.error());
        std::uint64_t end = 0;
        if (!checked_add_u64(offset.value(), item.second.bytes.size(), end)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "persisted overlay patch range overflows",
                "overlay_journal.load"));
        }
        for (const auto& existing : patch_ranges) {
            if (offset.value() < existing.second && existing.first < end) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "persisted overlay contains overlapping patches",
                    "overlay_journal.load"));
            }
        }
        patch_ranges.emplace_back(offset.value(), end);
    }
    {
        std::unique_lock<std::shared_mutex> lock(state_mutex_);
        items_ = std::move(items);
        revision_ = state.revision;
        history_cursor_ = state.cursor;
        history_epoch_ = state.epoch;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<overlay_transaction_result_t> overlay_journal_t::transact(
    const overlay_transaction_request_t& request,
    const cancellation_token_t& cancel) {
    auto workspace = workspace_.lock();
    if (!workspace || workspace->closing()) {
        return workspace_result_t<overlay_transaction_result_t>::failure(make_workspace_error(
            workspace_error_code_t::workspace_closing,
            "overlay workspace is closing", "overlay_journal.transact"));
    }
    if (request.operations.empty() || request.operations.size() > limits_.max_operations) {
        return workspace_result_t<overlay_transaction_result_t>::failure(make_workspace_error(
            request.operations.empty() ? workspace_error_code_t::invalid_argument
                                       : workspace_error_code_t::limit_exceeded,
            request.operations.empty() ? "overlay transaction has no operations"
                                       : "overlay transaction exceeds operation limit",
            "overlay_journal.transact"));
    }
    if (request.idempotency_key &&
        (request.idempotency_key->empty() ||
         request.idempotency_key->size() > limits_.max_idempotency_key_bytes ||
         contains_nul(*request.idempotency_key))) {
        return workspace_result_t<overlay_transaction_result_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "idempotency key is empty, too long, or contains NUL",
            "overlay_journal.transact"));
    }

    std::unique_lock<std::shared_mutex> mutation_lock(workspace->mutation_mutex());
    std::size_t total_patch_bytes = 0;
    std::vector<std::string> keys;
    keys.reserve(request.operations.size());
    std::unordered_map<std::string, std::pair<std::uint64_t, std::uint64_t>> patch_ranges;
    for (const auto& operation : request.operations) {
        auto validated = validate_operation(operation, limits_, *workspace, total_patch_bytes);
        if (!validated)
            return workspace_result_t<overlay_transaction_result_t>::failure(validated.error());
        const std::string key = entity_key(operation);
        if (std::find(keys.begin(), keys.end(), key) != keys.end()) {
            return workspace_result_t<overlay_transaction_result_t>::failure(make_workspace_error(
                workspace_error_code_t::revision_conflict,
                "overlay transaction contains duplicate entity operations",
                "overlay_journal.transact"));
        }
        keys.push_back(key);
        if (!operation.bytes.empty()) {
            auto patch_offset = patch_provider_offset(operation, *workspace);
            if (!patch_offset)
                return workspace_result_t<overlay_transaction_result_t>::failure(
                    patch_offset.error());
            std::uint64_t end = 0;
            if (!checked_add_u64(patch_offset.value(), operation.bytes.size(), end)) {
                return workspace_result_t<overlay_transaction_result_t>::failure(make_workspace_error(
                    workspace_error_code_t::range_overflow,
                    "overlay patch range overflows", "overlay_journal.transact"));
            }
            for (const auto& existing : patch_ranges) {
                if (patch_offset.value() < existing.second.second && existing.second.first < end) {
                    return workspace_result_t<overlay_transaction_result_t>::failure(make_workspace_error(
                        workspace_error_code_t::revision_conflict,
                        "overlay transaction contains overlapping patches",
                        "overlay_journal.transact"));
                }
            }
            patch_ranges.emplace(key, std::make_pair(patch_offset.value(), end));
        }
    }

    std::string request_hash;
    if (!request.dry_run) {
        json request_json;
        request_json["expected_revision"] = request.expected_revision
            ? json(std::to_string(*request.expected_revision)) : json(nullptr);
        request_json["idempotency_key"] = request.idempotency_key
            ? json(*request.idempotency_key) : json(nullptr);
        request_json["operations"] = json::array();
        for (const auto& operation : request.operations)
            request_json["operations"].push_back(operation_json(operation));
        auto request_hash_result = sha256_text(request_json.dump(), cancel);
        if (!request_hash_result)
            return workspace_result_t<overlay_transaction_result_t>::failure(
                request_hash_result.error());
        request_hash = request_hash_result.value().to_hex();
    }

    if (request.idempotency_key && !request.dry_run) {
        std::optional<overlay_transaction_result_t> replay;
        auto lookup = database_->with_reader(
            [&](sqlite3* reader) -> workspace_result_t<void> {
                overlay_statement_t statement;
                auto current = statement.prepare(reader,
                    "SELECT request_hash,result_json FROM overlay_idempotency WHERE idempotency_key=?1",
                    "overlay_journal.replay");
                if (!current)
                    return current;
                current = statement.bind_text(1, *request.idempotency_key);
                if (!current)
                    return current;
                const int status = sqlite3_step(statement.get());
                if (status == SQLITE_DONE)
                    return workspace_result_t<void>::success();
                if (status != SQLITE_ROW) {
                    auto error = make_workspace_error(
                        workspace_error_code_t::persistence_failure,
                        "unable to query overlay idempotency replay",
                        "overlay_journal.replay");
                    error.sqlite_status = status;
                    return workspace_result_t<void>::failure(std::move(error));
                }
                if (overlay_column_text(statement.get(), 0) != request_hash) {
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::revision_conflict,
                        "idempotency key was already used for a different transaction",
                        "overlay_journal.replay"));
                }
                auto parsed = parse_transaction_result(
                    overlay_column_text(statement.get(), 1));
                if (!parsed)
                    return workspace_result_t<void>::failure(parsed.error());
                replay = parsed.take_value();
                replay->idempotent_replay = true;
                return workspace_result_t<void>::success();
            });
        if (!lookup)
            return workspace_result_t<overlay_transaction_result_t>::failure(lookup.error());
        if (replay)
            return workspace_result_t<overlay_transaction_result_t>::success(
                std::move(*replay));
    }

    std::unordered_map<std::string, std::pair<std::uint64_t, std::uint64_t>> existing_patch_ranges;
    {
        std::shared_lock<std::shared_mutex> state_lock(state_mutex_);
        for (const auto& item : items_) {
            if (item.second.bytes.empty())
                continue;
            auto offset = patch_provider_offset(item.second, *workspace);
            if (!offset)
                return workspace_result_t<overlay_transaction_result_t>::failure(offset.error());
            std::uint64_t end = 0;
            if (!checked_add_u64(offset.value(), item.second.bytes.size(), end)) {
                return workspace_result_t<overlay_transaction_result_t>::failure(
                    make_workspace_error(workspace_error_code_t::range_overflow,
                        "existing overlay patch range overflows",
                        "overlay_journal.transact"));
            }
            existing_patch_ranges.emplace(item.first,
                std::make_pair(offset.value(), end));
        }
    }
    for (const auto& patch : patch_ranges) {
        for (const auto& existing : existing_patch_ranges) {
            if (existing.first == patch.first)
                continue;
            if (patch.second.first < existing.second.second &&
                existing.second.first < patch.second.second) {
                return workspace_result_t<overlay_transaction_result_t>::failure(
                    make_workspace_error(workspace_error_code_t::revision_conflict,
                        "overlay patch overlaps an existing patch",
                        "overlay_journal.transact"));
            }
        }
    }

    std::uint64_t local_revision = 0;
    {
        std::shared_lock<std::shared_mutex> lock(state_mutex_);
        local_revision = revision_;
    }
    {
        auto auth_check = database_->with_reader(
            [&](sqlite3* reader) -> workspace_result_t<void> {
                auto state_result = read_overlay_state(reader, "overlay_journal.transact");
                if (!state_result) return workspace_result_t<void>::failure(state_result.error());
                if (state_result.value().revision != local_revision)
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::revision_conflict,
                        "authoritative revision mismatch", "overlay_journal.transact"));
                return workspace_result_t<void>::success();
            });
        if (!auth_check)
            return workspace_result_t<overlay_transaction_result_t>::failure(auth_check.error());
    }
    if (request.expected_revision && *request.expected_revision != local_revision) {
        return workspace_result_t<overlay_transaction_result_t>::failure(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "overlay expected revision does not match current revision",
            "overlay_journal.transact"));
    }
    if (workspace->overlay_revision() != local_revision) {
        return workspace_result_t<overlay_transaction_result_t>::failure(make_workspace_error(
            workspace_error_code_t::stale_generation,
            "workspace and overlay journal revisions differ",
            "overlay_journal.transact"));
    }

    overlay_transaction_result_t dry_result;
    dry_result.revision = local_revision;
    dry_result.dry_run = request.dry_run;
    dry_result.committed = false;
    for (std::size_t index = 0; index < request.operations.size(); ++index)
        dry_result.operations.push_back({index, keys[index], removes_value(request.operations[index])});
    if (request.dry_run)
        return workspace_result_t<overlay_transaction_result_t>::success(std::move(dry_result));

    auto result_holder = std::make_shared<overlay_transaction_result_t>();
    const auto operations = request.operations;
    const auto idempotency = request.idempotency_key;
    auto ticket = database_->enqueue_write("analysis.overlay.commit",
        [operations, keys, idempotency, request_hash, request_expected = request.expected_revision,
         result_holder](sqlite3* writer, const cancellation_token_t& token) -> workspace_result_t<void> {
            if (token.stop_requested())
                return workspace_result_t<void>::failure(make_workspace_error(
                    token.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                              : workspace_error_code_t::cancelled,
                    "overlay commit cancelled", "overlay_journal.commit"));
            auto begin = overlay_exec(writer, "BEGIN IMMEDIATE", "overlay_journal.commit");
            if (!begin) return begin;
            auto state_result = read_overlay_state(writer, "overlay_journal.commit");
            if (!state_result) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return workspace_result_t<void>::failure(state_result.error()); }
            auto state = state_result.take_value();
            if (idempotency) {
                overlay_statement_t idempotency_query;
                auto current = idempotency_query.prepare(writer,
                    "SELECT request_hash,result_json FROM overlay_idempotency WHERE idempotency_key=?1",
                    "overlay_journal.commit");
                if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                current = idempotency_query.bind_text(1, *idempotency); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                const int status = sqlite3_step(idempotency_query.get());
                if (status == SQLITE_ROW) {
                    if (overlay_column_text(idempotency_query.get(), 0) != request_hash) {
                        overlay_exec(writer, "ROLLBACK", "overlay_journal.commit");
                        return workspace_result_t<void>::failure(make_workspace_error(
                            workspace_error_code_t::revision_conflict,
                            "idempotency key was already used for a different transaction",
                            "overlay_journal.commit"));
                    }
                    auto prior = parse_transaction_result(overlay_column_text(idempotency_query.get(), 1));
                    if (!prior) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return workspace_result_t<void>::failure(prior.error()); }
                    *result_holder = prior.take_value();
                    result_holder->idempotent_replay = true;
                    overlay_exec(writer, "ROLLBACK", "overlay_journal.commit");
                    return workspace_result_t<void>::success();
                }
                if (status != SQLITE_DONE) {
                    overlay_exec(writer, "ROLLBACK", "overlay_journal.commit");
                    auto error = make_workspace_error(workspace_error_code_t::persistence_failure,
                        "unable to query overlay idempotency key", "overlay_journal.commit");
                    error.sqlite_status = status;
                    return workspace_result_t<void>::failure(std::move(error));
                }
            }
            if (request_expected && *request_expected != state.revision) {
                overlay_exec(writer, "ROLLBACK", "overlay_journal.commit");
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::revision_conflict,
                    "overlay database revision conflict", "overlay_journal.commit"));
            }

            const auto sqlite_integer_max = static_cast<std::uint64_t>(
                (std::numeric_limits<std::int64_t>::max)());
            if (state.revision >= sqlite_integer_max ||
                state.next_transaction >= sqlite_integer_max) {
                overlay_exec(writer, "ROLLBACK", "overlay_journal.commit");
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::range_overflow,
                    "overlay revision or transaction identifier exhausted SQLite range",
                    "overlay_journal.commit"));
            }

            overlay_statement_t abandon;
            auto current = abandon.prepare(writer,
                "UPDATE overlay_transactions SET abandoned=1 WHERE applied=0 AND abandoned=0 AND transaction_id>?1",
                "overlay_journal.commit");
            if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
            current = abandon.bind_uint(1, state.cursor); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
            current = abandon.step_done(); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
            if (sqlite3_changes(writer) > 0)
                ++state.epoch;

            const std::uint64_t transaction_id = state.next_transaction;
            const std::uint64_t new_revision = state.revision + 1;
            overlay_transaction_result_t transaction_result;
            transaction_result.transaction_id = transaction_id;
            transaction_result.revision = new_revision;
            transaction_result.committed = true;
            for (std::size_t index = 0; index < operations.size(); ++index)
                transaction_result.operations.push_back({index, keys[index], removes_value(operations[index])});
            const std::string result_json = transaction_result_json(transaction_result).dump();

            overlay_statement_t transaction_statement;
            current = transaction_statement.prepare(writer,
                "INSERT INTO overlay_transactions(transaction_id,revision,history_epoch,history_ordinal,idempotency_key,request_hash,committed_utc_ms,applied,abandoned,result_json) VALUES(?1,?2,?3,?4,?5,?6,?7,1,0,?8)",
                "overlay_journal.commit");
            if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
            current = transaction_statement.bind_uint(1, transaction_id); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
            current = transaction_statement.bind_uint(2, new_revision); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
            current = transaction_statement.bind_uint(3, state.epoch); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
            current = transaction_statement.bind_uint(4, transaction_id); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
            if (idempotency) current = transaction_statement.bind_text(5, *idempotency); else current = transaction_statement.bind_null(5); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
            current = transaction_statement.bind_text(6, request_hash); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
            current = transaction_statement.bind_uint(7, overlay_utc_ms()); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
            current = transaction_statement.bind_text(8, result_json); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
            current = transaction_statement.step_done(); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }

            overlay_statement_t prior_query;
            current = prior_query.prepare(writer,
                "SELECT payload_json FROM overlay_items WHERE entity_key=?1",
                "overlay_journal.commit");
            if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
            overlay_statement_t operation_statement;
            current = operation_statement.prepare(writer,
                "INSERT INTO overlay_operations(transaction_id,operation_index,kind,entity_key,address_space,address_value,address_arch,address_mode,before_json,after_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                "overlay_journal.commit");
            if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
            for (std::size_t index = 0; index < operations.size(); ++index) {
                current = prior_query.bind_text(1, keys[index]); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                const int prior_status = sqlite3_step(prior_query.get());
                std::optional<std::string> before;
                if (prior_status == SQLITE_ROW)
                    before = overlay_column_text(prior_query.get(), 0);
                else if (prior_status != SQLITE_DONE) {
                    overlay_exec(writer, "ROLLBACK", "overlay_journal.commit");
                    auto error = make_workspace_error(workspace_error_code_t::persistence_failure,
                        "unable to query prior overlay item", "overlay_journal.commit");
                    error.sqlite_status = prior_status;
                    return workspace_result_t<void>::failure(std::move(error));
                }
                current = prior_query.reset(); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                const std::string after = removes_value(operations[index])
                    ? std::string("null") : operation_json(operations[index]).dump();
                current = operation_statement.bind_uint(1, transaction_id); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                current = operation_statement.bind_uint(2, index); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                current = operation_statement.bind_int(3, static_cast<std::int64_t>(operations[index].kind)); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                current = operation_statement.bind_text(4, keys[index]); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                current = bind_operation_address(operation_statement, 5, operations[index].address); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                if (before) current = operation_statement.bind_text(9, *before); else current = operation_statement.bind_null(9); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                current = operation_statement.bind_text(10, after); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                current = operation_statement.step_done(); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                current = operation_statement.reset(); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                current = apply_item(writer, keys[index], operations[index].kind,
                                     operations[index].address, after, new_revision);
                if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
            }

            overlay_statement_t state_statement;
            current = state_statement.prepare(writer,
                "UPDATE overlay_state SET revision=?1,history_cursor=?2,next_transaction_id=?3,history_epoch=?4,updated_utc_ms=?5 WHERE singleton=1",
                "overlay_journal.commit");
            if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
            current = state_statement.bind_uint(1, new_revision); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
            current = state_statement.bind_uint(2, transaction_id); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
            current = state_statement.bind_uint(3, transaction_id + 1); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
            current = state_statement.bind_uint(4, state.epoch); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
            current = state_statement.bind_uint(5, overlay_utc_ms()); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
            current = state_statement.step_done(); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }

            if (idempotency) {
                overlay_statement_t idempotency_statement;
                current = idempotency_statement.prepare(writer,
                    "INSERT INTO overlay_idempotency(idempotency_key,request_hash,result_json,transaction_id,created_utc_ms) VALUES(?1,?2,?3,?4,?5)",
                    "overlay_journal.commit");
                if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                current = idempotency_statement.bind_text(1, *idempotency); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                current = idempotency_statement.bind_text(2, request_hash); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                current = idempotency_statement.bind_text(3, result_json); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                current = idempotency_statement.bind_uint(4, transaction_id); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                current = idempotency_statement.bind_uint(5, overlay_utc_ms()); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                current = idempotency_statement.step_done(); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
            }
            auto committed = overlay_exec(writer, "COMMIT", "overlay_journal.commit");
            if (!committed) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return committed; }
            *result_holder = std::move(transaction_result);
            return workspace_result_t<void>::success();
        }, cancel);
    auto waited = wait_ticket(ticket, cancel);
    if (!waited)
        return workspace_result_t<overlay_transaction_result_t>::failure(waited.error());
    if (!result_holder->idempotent_replay) {
        auto advanced = workspace->advance_overlay_revision(local_revision);
        if (!advanced)
            return workspace_result_t<overlay_transaction_result_t>::failure(advanced.error());
        auto loaded = reload_items();
        if (!loaded)
            return workspace_result_t<overlay_transaction_result_t>::failure(loaded.error());
    }
    return workspace_result_t<overlay_transaction_result_t>::success(*result_holder);
}

workspace_result_t<overlay_transaction_result_t> overlay_journal_t::history_action(
    bool redo,
    std::optional<std::uint64_t> expected_revision,
    const cancellation_token_t& cancel) {
    auto workspace = workspace_.lock();
    if (!workspace || workspace->closing()) {
        return workspace_result_t<overlay_transaction_result_t>::failure(make_workspace_error(
            workspace_error_code_t::workspace_closing,
            "overlay workspace is closing", "overlay_journal.history"));
    }
    std::unique_lock<std::shared_mutex> mutation_lock(workspace->mutation_mutex());
    const auto local_snapshot = snapshot();
    {
        auto auth_check = database_->with_reader(
            [&](sqlite3* reader) -> workspace_result_t<void> {
                auto state_result = read_overlay_state(reader, "overlay_journal.history");
                if (!state_result) return workspace_result_t<void>::failure(state_result.error());
                if (state_result.value().revision != local_snapshot.revision)
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::revision_conflict,
                        "authoritative revision mismatch", "overlay_journal.history"));
                return workspace_result_t<void>::success();
            });
        if (!auth_check)
            return workspace_result_t<overlay_transaction_result_t>::failure(auth_check.error());
    }
    if (expected_revision && *expected_revision != local_snapshot.revision) {
        return workspace_result_t<overlay_transaction_result_t>::failure(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "overlay expected revision does not match current revision",
            "overlay_journal.history"));
    }
    auto result_holder = std::make_shared<overlay_transaction_result_t>();
    auto ticket = database_->enqueue_write(
        redo ? "analysis.overlay.redo" : "analysis.overlay.undo",
        [redo, expected_revision, result_holder](sqlite3* writer,
                                                 const cancellation_token_t& token) {
            if (token.stop_requested())
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::cancelled,
                    "overlay history action cancelled", "overlay_journal.history"));
            auto begin = overlay_exec(writer, "BEGIN IMMEDIATE", "overlay_journal.history");
            if (!begin) return begin;
            auto state_result = read_overlay_state(writer, "overlay_journal.history");
            if (!state_result) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return workspace_result_t<void>::failure(state_result.error()); }
            auto state = state_result.take_value();
            if (expected_revision && *expected_revision != state.revision) {
                overlay_exec(writer, "ROLLBACK", "overlay_journal.history");
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::revision_conflict,
                    "overlay database revision conflict", "overlay_journal.history"));
            }
            if (state.revision >= static_cast<std::uint64_t>(
                    (std::numeric_limits<std::int64_t>::max)())) {
                overlay_exec(writer, "ROLLBACK", "overlay_journal.history");
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::range_overflow,
                    "overlay revision exhausted SQLite range",
                    "overlay_journal.history"));
            }
            overlay_statement_t target_statement;
            auto current = target_statement.prepare(writer,
                redo
                    ? "SELECT transaction_id FROM overlay_transactions WHERE applied=0 AND abandoned=0 AND transaction_id>?1 ORDER BY transaction_id LIMIT 1"
                    : "SELECT transaction_id FROM overlay_transactions WHERE applied=1 AND abandoned=0 AND transaction_id<=?1 ORDER BY transaction_id DESC LIMIT 1",
                "overlay_journal.history");
            if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }
            current = target_statement.bind_uint(1, state.cursor); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }
            int status = sqlite3_step(target_statement.get());
            if (status == SQLITE_DONE) {
                overlay_exec(writer, "ROLLBACK", "overlay_journal.history");
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::target_not_found,
                    redo ? "no overlay transaction is available to redo"
                         : "no overlay transaction is available to undo",
                    "overlay_journal.history"));
            }
            if (status != SQLITE_ROW) {
                overlay_exec(writer, "ROLLBACK", "overlay_journal.history");
                auto error = make_workspace_error(workspace_error_code_t::persistence_failure,
                    "unable to select overlay history transaction", "overlay_journal.history");
                error.sqlite_status = status;
                return workspace_result_t<void>::failure(std::move(error));
            }
            const std::uint64_t transaction_id = static_cast<std::uint64_t>(sqlite3_column_int64(target_statement.get(), 0));
            const std::uint64_t new_revision = state.revision + 1;
            overlay_statement_t operation_statement;
            current = operation_statement.prepare(writer,
                redo
                    ? "SELECT entity_key,kind,address_space,address_value,address_arch,address_mode,after_json,operation_index FROM overlay_operations WHERE transaction_id=?1 ORDER BY operation_index"
                    : "SELECT entity_key,kind,address_space,address_value,address_arch,address_mode,before_json,operation_index FROM overlay_operations WHERE transaction_id=?1 ORDER BY operation_index DESC",
                "overlay_journal.history");
            if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }
            current = operation_statement.bind_uint(1, transaction_id); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }
            overlay_transaction_result_t action_result;
            action_result.transaction_id = transaction_id;
            action_result.revision = new_revision;
            action_result.committed = true;
            for (;;) {
                status = sqlite3_step(operation_statement.get());
                if (status == SQLITE_DONE)
                    break;
                if (status != SQLITE_ROW) {
                    overlay_exec(writer, "ROLLBACK", "overlay_journal.history");
                    auto error = make_workspace_error(workspace_error_code_t::persistence_failure,
                        "unable to read overlay history operations", "overlay_journal.history");
                    error.sqlite_status = status;
                    return workspace_result_t<void>::failure(std::move(error));
                }
                const std::string key = overlay_column_text(operation_statement.get(), 0);
                const auto kind = static_cast<overlay_operation_kind_t>(sqlite3_column_int(operation_statement.get(), 1));
                address_t address;
                address.space = static_cast<address_space_id_t>(sqlite3_column_int(operation_statement.get(), 2));
                address.value = static_cast<std::uint64_t>(sqlite3_column_int64(operation_statement.get(), 3));
                address.architecture = static_cast<architecture_id_t>(sqlite3_column_int(operation_statement.get(), 4));
                address.mode = static_cast<architecture_mode_t>(sqlite3_column_int(operation_statement.get(), 5));
                const std::string payload = sqlite3_column_type(operation_statement.get(), 6) == SQLITE_NULL
                    ? std::string("null") : overlay_column_text(operation_statement.get(), 6);
                current = apply_item(writer, key, kind, address, payload, new_revision);
                if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }
                action_result.operations.push_back({
                    static_cast<std::size_t>(sqlite3_column_int64(operation_statement.get(), 7)),
                    key, payload == "null"});
            }

            overlay_statement_t applied_statement;
            current = applied_statement.prepare(writer,
                redo ? "UPDATE overlay_transactions SET applied=1 WHERE transaction_id=?1"
                     : "UPDATE overlay_transactions SET applied=0 WHERE transaction_id=?1",
                "overlay_journal.history");
            if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }
            current = applied_statement.bind_uint(1, transaction_id); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }
            current = applied_statement.step_done(); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }

            std::uint64_t cursor = transaction_id;
            if (!redo) {
                overlay_statement_t previous;
                current = previous.prepare(writer,
                    "SELECT COALESCE(MAX(transaction_id),0) FROM overlay_transactions WHERE applied=1 AND abandoned=0 AND transaction_id<?1",
                    "overlay_journal.history");
                if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }
                current = previous.bind_uint(1, transaction_id); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }
                status = sqlite3_step(previous.get());
                if (status != SQLITE_ROW) {
                    overlay_exec(writer, "ROLLBACK", "overlay_journal.history");
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::persistence_failure,
                        "unable to calculate overlay history cursor",
                        "overlay_journal.history"));
                }
                cursor = static_cast<std::uint64_t>(sqlite3_column_int64(previous.get(), 0));
            }

            overlay_statement_t state_statement;
            current = state_statement.prepare(writer,
                "UPDATE overlay_state SET revision=?1,history_cursor=?2,updated_utc_ms=?3 WHERE singleton=1",
                "overlay_journal.history");
            if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }
            current = state_statement.bind_uint(1, new_revision); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }
            current = state_statement.bind_uint(2, cursor); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }
            current = state_statement.bind_uint(3, overlay_utc_ms()); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }
            current = state_statement.step_done(); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }

            overlay_statement_t event_statement;
            current = event_statement.prepare(writer,
                "INSERT INTO overlay_history_events(event_kind,source_transaction_id,resulting_revision,history_epoch,history_cursor,created_utc_ms) VALUES(?1,?2,?3,?4,?5,?6)",
                "overlay_journal.history");
            if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }
            current = event_statement.bind_int(1, redo ? 2 : 1); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }
            current = event_statement.bind_uint(2, transaction_id); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }
            current = event_statement.bind_uint(3, new_revision); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }
            current = event_statement.bind_uint(4, state.epoch); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }
            current = event_statement.bind_uint(5, cursor); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }
            current = event_statement.bind_uint(6, overlay_utc_ms()); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }
            current = event_statement.step_done(); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }
            auto committed = overlay_exec(writer, "COMMIT", "overlay_journal.history");
            if (!committed) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return committed; }
            *result_holder = std::move(action_result);
            return workspace_result_t<void>::success();
        }, cancel);
    auto waited = wait_ticket(ticket, cancel);
    if (!waited)
        return workspace_result_t<overlay_transaction_result_t>::failure(waited.error());
    auto advanced = workspace->advance_overlay_revision(local_snapshot.revision);
    if (!advanced)
        return workspace_result_t<overlay_transaction_result_t>::failure(advanced.error());
    auto loaded = reload_items();
    if (!loaded)
        return workspace_result_t<overlay_transaction_result_t>::failure(loaded.error());
    return workspace_result_t<overlay_transaction_result_t>::success(*result_holder);
}

workspace_result_t<overlay_transaction_result_t> overlay_journal_t::undo(
    std::optional<std::uint64_t> expected_revision,
    const cancellation_token_t& cancel) {
    return history_action(false, expected_revision, cancel);
}

workspace_result_t<overlay_transaction_result_t> overlay_journal_t::redo(
    std::optional<std::uint64_t> expected_revision,
    const cancellation_token_t& cancel) {
    return history_action(true, expected_revision, cancel);
}

overlay_snapshot_t overlay_journal_t::snapshot() const {
    std::shared_lock<std::shared_mutex> lock(state_mutex_);
    overlay_snapshot_t result;
    result.revision = revision_;
    result.history_cursor = history_cursor_;
    result.history_epoch = history_epoch_;
    result.items.reserve(items_.size());
    for (const auto& item : items_)
        result.items.push_back(item);
    std::sort(result.items.begin(), result.items.end(),
        [](const auto& lhs, const auto& rhs) { return lhs.first < rhs.first; });
    return result;
}

std::optional<overlay_operation_t> overlay_journal_t::find(
    const std::string& entity) const {
    std::shared_lock<std::shared_mutex> lock(state_mutex_);
    auto found = items_.find(entity);
    if (found == items_.end())
        return std::nullopt;
    return found->second;
}

std::vector<overlay_operation_t> overlay_journal_t::patch_operations() const {
    std::vector<overlay_operation_t> result;
    std::shared_lock<std::shared_mutex> lock(state_mutex_);
    for (const auto& item : items_) {
        if (item.second.kind == overlay_operation_kind_t::byte_patch ||
            item.second.kind == overlay_operation_kind_t::assembly_patch ||
            item.second.kind == overlay_operation_kind_t::integer_patch)
            result.push_back(item.second);
    }
    std::sort(result.begin(), result.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.address < rhs.address;
    });
    return result;
}

void overlay_journal_t::request_cancel() noexcept {
    cancellation_.request_cancel();
}

workspace_result_t<void>
overlay_journal_t::drain(std::chrono::steady_clock::time_point deadline) {
    return database_ ? database_->queue()->drain(deadline)
                     : workspace_result_t<void>::success();
}

}
