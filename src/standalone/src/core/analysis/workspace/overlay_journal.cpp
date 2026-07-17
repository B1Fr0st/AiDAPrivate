#include "overlay_journal.hpp"

#include "../incremental_reanalysis.hpp"
#include "../overlay_projection.hpp"
#include "../provider_snapshot.hpp"
#include "../spill_provider.hpp"
#include "checked_range.hpp"
#include "decompiler_service.hpp"
#include "../decompiler/managed_entity_binding.hpp"

#include <sqlite3.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <charconv>
#include <array>
#include <chrono>
#include <cctype>
#include <cstring>
#include <functional>
#include <future>
#include <limits>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <utility>

namespace aida::analysis {

namespace {

using json = nlohmann::json;

bool same_target_binding(const overlay_target_identity_v9_t& lhs,
                         const overlay_target_identity_v9_t& rhs) noexcept {
    return lhs.image_hash == rhs.image_hash &&
        lhs.provenance_hash == rhs.provenance_hash &&
        lhs.image_base == rhs.image_base && lhs.image_size == rhs.image_size &&
        lhs.kind == rhs.kind && lhs.architecture == rhs.architecture &&
        lhs.address_width == rhs.address_width && lhs.reserved == rhs.reserved;
}

overlay_target_identity_v9_t target_at_generation(
    overlay_target_identity_v9_t target,
    std::uint64_t generation) noexcept {
    target.generation = generation;
    return target;
}

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

    workspace_result_t<void> bind_blob(int index, const void* value,
                                       std::size_t size) {
        if ((!value && size != 0) ||
            size > static_cast<std::size_t>(
                       (std::numeric_limits<int>::max)()))
            return workspace_result_t<void>::failure(
                error(SQLITE_TOOBIG, "overlay blob exceeds SQLite limit"));
        return bind(sqlite3_bind_blob(statement_, index, value,
                                      static_cast<int>(size), SQLITE_TRANSIENT));
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

class overlay_rollback_guard_t final {
public:
    explicit overlay_rollback_guard_t(sqlite3* database) noexcept
        : database_(database) {
    }

    ~overlay_rollback_guard_t() {
        if (database_ && sqlite3_get_autocommit(database_) == 0)
            static_cast<void>(sqlite3_exec(
                database_, "ROLLBACK", nullptr, nullptr, nullptr));
    }

private:
    sqlite3* database_ = nullptr;
};

workspace_result_t<void> persist_fixed_target(
    sqlite3* database,
    const overlay_target_identity_v9_t& target,
    const char* phase) {
    std::string serialized;
    try {
        serialized = serialize_overlay_target_identity_v9(target);
    } catch (...) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "fixed overlay target identity cannot be serialized", phase));
    }
    overlay_statement_t statement;
    auto result = statement.prepare(database,
        "INSERT INTO metadata(key,value) VALUES('overlay_v9_fixed_target',?1) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        phase);
    if (result)
        result = statement.bind_text(1, serialized);
    if (result)
        result = statement.step_done();
    return result;
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

template <std::size_t Size>
std::string fixed_hex_encode(const std::array<std::uint8_t, Size>& bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result(Size * 2, '0');
    for (std::size_t index = 0; index < Size; ++index) {
        result[index * 2] = digits[bytes[index] >> 4];
        result[index * 2 + 1] = digits[bytes[index] & 15];
    }
    return result;
}

std::string string_hex_encode(const std::string& bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result(bytes.size() * 2, '0');
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        const auto byte = static_cast<unsigned char>(bytes[index]);
        result[index * 2] = digits[byte >> 4];
        result[index * 2 + 1] = digits[byte & 15];
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

template <std::size_t Size>
bool fixed_hex_decode(const std::string& text,
                      std::array<std::uint8_t, Size>& result) noexcept {
    if (text.size() != Size * 2)
        return false;
    const auto value = [](char character) noexcept -> int {
        if (character >= '0' && character <= '9') return character - '0';
        if (character >= 'a' && character <= 'f') return character - 'a' + 10;
        return -1;
    };
    for (std::size_t index = 0; index < Size; ++index) {
        const int high = value(text[index * 2]);
        const int low = value(text[index * 2 + 1]);
        if (high < 0 || low < 0)
            return false;
        result[index] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return true;
}

bool string_hex_decode(const std::string& text, std::string& result) {
    if ((text.size() & 1U) != 0)
        return false;
    const auto value = [](char character) noexcept -> int {
        if (character >= '0' && character <= '9') return character - '0';
        if (character >= 'a' && character <= 'f') return character - 'a' + 10;
        return -1;
    };
    result.resize(text.size() / 2);
    for (std::size_t index = 0; index < result.size(); ++index) {
        const int high = value(text[index * 2]);
        const int low = value(text[index * 2 + 1]);
        if (high < 0 || low < 0)
            return false;
        result[index] = static_cast<char>((high << 4) | low);
    }
    return true;
}

json managed_locator_json(
    const overlay_managed_entity_locator_v9_t& locator) {
    return json{{"artifact_hash", fixed_hex_encode(locator.artifact_hash)},
                {"entity_hash", fixed_hex_encode(locator.entity_hash)},
                {"generation", std::to_string(locator.generation)},
                {"provider_hash", fixed_hex_encode(locator.provider_hash)},
                {"provider_size", std::to_string(locator.provider_size)},
                {"serialized_entity", string_hex_encode(locator.serialized_entity)},
                {"workspace_id", fixed_hex_encode(locator.workspace_id)}};
}

std::optional<overlay_managed_entity_locator_v9_t> parse_managed_locator_json(
    const json& value) noexcept {
    try {
        static constexpr std::array<const char*, 7> fields{{
            "artifact_hash", "entity_hash", "generation", "provider_hash",
            "provider_size", "serialized_entity", "workspace_id"}};
        if (!value.is_object() || value.size() != fields.size() ||
            !std::all_of(fields.begin(), fields.end(),
                [&](const char* field) {
                    return value.contains(field) && value[field].is_string();
                }))
            return std::nullopt;
        overlay_managed_entity_locator_v9_t locator;
        const auto parse_uint = [](const std::string& text,
                                   std::uint64_t& output) noexcept {
            const auto parsed = std::from_chars(
                text.data(), text.data() + text.size(), output, 10);
            return !text.empty() && parsed.ec == std::errc{} &&
                parsed.ptr == text.data() + text.size();
        };
        const auto& serialized_entity =
            value["serialized_entity"].get_ref<const std::string&>();
        if (serialized_entity.empty() ||
            serialized_entity.size() >
                k_overlay_managed_entity_serialization_limit * 2U ||
            (serialized_entity.size() & 1U) != 0)
            return std::nullopt;
        if (!fixed_hex_decode(value["workspace_id"].get_ref<const std::string&>(),
                              locator.workspace_id) ||
            !fixed_hex_decode(value["provider_hash"].get_ref<const std::string&>(),
                              locator.provider_hash) ||
            !fixed_hex_decode(value["artifact_hash"].get_ref<const std::string&>(),
                              locator.artifact_hash) ||
            !fixed_hex_decode(value["entity_hash"].get_ref<const std::string&>(),
                              locator.entity_hash) ||
            !parse_uint(value["provider_size"].get_ref<const std::string&>(),
                        locator.provider_size) ||
            !parse_uint(value["generation"].get_ref<const std::string&>(),
                        locator.generation) ||
            !string_hex_decode(serialized_entity, locator.serialized_entity) ||
            !locator.valid())
            return std::nullopt;
        return locator;
    } catch (...) {
        return std::nullopt;
    }
}

json operation_json(const overlay_operation_t& operation,
                    const overlay_target_identity_v9_t* target = nullptr) {
    json result{{"address", address_json(operation.address)},
                {"assembly", operation.assembly},
                {"bytes", hex_encode(operation.bytes)},
                {"integer_type", operation.integer_type},
                {"integer_value", operation.integer_value},
                {"kind", static_cast<unsigned>(operation.kind)},
                {"name", operation.name},
                {"reanalysis_flags", operation.reanalysis_flags},
                {"remove", operation.remove},
                {"signature", operation.signature},
                {"stack_offset", std::to_string(operation.stack_offset)},
                {"text", operation.text},
                {"type", operation.type},
                {"variable", operation.variable}};
    result["end"] = operation.end ? address_json(*operation.end) : json(nullptr);
    if (target) {
        result["schema"] = k_overlay_journal_v9_schema;
        result["target"] = json::parse(serialize_overlay_target_identity_v9(*target));
    }
    if (operation.target_discriminator ==
            overlay_target_discriminator_v9_t::managed_entity &&
        operation.managed_locator) {
        result.erase("address");
        result.erase("end");
        result["target_discriminator"] = static_cast<std::uint8_t>(
            operation.target_discriminator);
        result["managed_locator"] = managed_locator_json(
            *operation.managed_locator);
    }
    return result;
}

json legacy_operation_json(const overlay_operation_t& operation) {
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

workspace_result_t<overlay_operation_t> parse_operation(
    const std::string& text,
    const overlay_target_identity_v9_t& expected_target) {
    auto value = json::parse(text, nullptr, false);
    if (value.is_discarded() || !value.is_object()) {
        return workspace_result_t<overlay_operation_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "overlay operation JSON is malformed", "overlay_journal.recovery"));
    }
    const std::array<const char*, 11> fields{{"assembly", "bytes", "integer_type",
        "integer_value", "kind", "name", "signature", "stack_offset", "text", "type", "variable"}};
    for (const char* field : fields) {
        if (!value.contains(field)) {
            return workspace_result_t<overlay_operation_t>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "overlay operation JSON is missing a required field",
                "overlay_journal.recovery"));
        }
    }
    const bool versioned = value.contains("schema");
    if (versioned) {
        const bool managed = value.contains("target_discriminator") ||
            value.contains("managed_locator");
        if (value.size() != 17U ||
            !value["schema"].is_number_unsigned() ||
            value["schema"].get<std::uint32_t>() != k_overlay_journal_v9_schema ||
            !value.contains("target") || !value.contains("reanalysis_flags") ||
            !value.contains("remove")) {
            return workspace_result_t<overlay_operation_t>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "overlay operation schema is invalid",
                "overlay_journal.recovery"));
        }
        auto serialized_target = deserialize_overlay_target_identity_v9(value["target"].dump());
        if (!serialized_target ||
            !same_target_binding(*serialized_target, expected_target)) {
            return workspace_result_t<overlay_operation_t>::failure(make_workspace_error(
                workspace_error_code_t::target_conflict,
                "overlay operation target identity does not match the workspace",
                "overlay_journal.recovery"));
        }
        if (managed) {
            if (!value.contains("target_discriminator") ||
                !value["target_discriminator"].is_number_unsigned() ||
                value["target_discriminator"].get<unsigned>() !=
                    static_cast<unsigned>(
                        overlay_target_discriminator_v9_t::managed_entity) ||
                !value.contains("managed_locator")) {
                return workspace_result_t<overlay_operation_t>::failure(
                    make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "managed overlay target discriminator is invalid",
                        "overlay_journal.recovery"));
            }
            if (value.contains("address") || value.contains("end")) {
                return workspace_result_t<overlay_operation_t>::failure(
                    make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "managed overlay record contains an address locator",
                        "overlay_journal.recovery"));
            }
        } else if (!value.contains("address") || !value.contains("end")) {
            return workspace_result_t<overlay_operation_t>::failure(
                make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "native overlay record omits its address locator",
                    "overlay_journal.recovery"));
        }
    }
    overlay_operation_t operation;
    if (versioned && value.contains("managed_locator")) {
        auto locator = parse_managed_locator_json(value["managed_locator"]);
        if (!locator) {
            return workspace_result_t<overlay_operation_t>::failure(
                make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "managed overlay locator is malformed or noncanonical",
                    "overlay_journal.recovery"));
        }
        operation.target_discriminator =
            overlay_target_discriminator_v9_t::managed_entity;
        operation.managed_locator = std::move(*locator);
    }
    if (operation.target_discriminator ==
        overlay_target_discriminator_v9_t::native_address) {
        auto address = parse_address(value["address"]);
        if (!address)
            return workspace_result_t<overlay_operation_t>::failure(
                address.error());
        operation.address = address.take_value();
        if (value.contains("end") && !value["end"].is_null()) {
            auto end = parse_address(value["end"]);
            if (!end)
                return workspace_result_t<overlay_operation_t>::failure(
                    end.error());
            operation.end = end.take_value();
        }
    }
    try {
        if (!value["kind"].is_number_unsigned())
            throw std::invalid_argument("invalid overlay operation kind");
        const auto ordinal = value["kind"].get<unsigned>();
        if (ordinal > static_cast<unsigned>(overlay_operation_kind_t::reanalysis) ||
            (!versioned && ordinal > static_cast<unsigned>(overlay_operation_kind_t::integer_patch)))
            throw std::invalid_argument("invalid overlay operation kind");
        operation.kind = static_cast<overlay_operation_kind_t>(ordinal);
        operation.assembly = value["assembly"].get<std::string>();
        operation.integer_type = value["integer_type"].get<std::string>();
        operation.integer_value = value["integer_value"].get<std::string>();
        operation.name = value["name"].get<std::string>();
        if (versioned) {
            operation.reanalysis_flags = value["reanalysis_flags"].get<std::uint32_t>();
            operation.remove = value["remove"].get<bool>();
        }
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
    if (operation.target_discriminator ==
            overlay_target_discriminator_v9_t::managed_entity &&
        operation.managed_locator) {
        std::string domain;
        switch (operation.kind) {
        case overlay_operation_kind_t::comment:
        case overlay_operation_kind_t::comment_update:
            domain = "comment";
            break;
        case overlay_operation_kind_t::name:
            domain = "name";
            break;
        case overlay_operation_kind_t::type_application:
        case overlay_operation_kind_t::type_update:
            domain = "type_application";
            break;
        default:
            domain = "invalid";
            break;
        }
        const auto& locator = *operation.managed_locator;
        const std::string qualifier =
            operation.kind == overlay_operation_kind_t::type_application ||
                    operation.kind == overlay_operation_kind_t::type_update
                ? (operation.variable.empty() ? operation.name
                                              : operation.variable)
                : std::string{};
        return "managed:" + domain + ":" +
            fixed_hex_encode(locator.workspace_id) + ":" +
            fixed_hex_encode(locator.provider_hash) + ":" +
            std::to_string(locator.provider_size) + ":" +
            fixed_hex_encode(locator.artifact_hash) + ":" +
            fixed_hex_encode(locator.entity_hash) + ":" +
            string_hex_encode(locator.serialized_entity) + ":" + qualifier;
    }
    std::string prefix;
    switch (operation.kind) {
    case overlay_operation_kind_t::comment:
    case overlay_operation_kind_t::comment_update:
        prefix = "comment";
        break;
    case overlay_operation_kind_t::name: prefix = "name"; break;
    case overlay_operation_kind_t::bookmark: prefix = "bookmark"; break;
    case overlay_operation_kind_t::type_declaration: return "type_declaration:" + operation.name;
    case overlay_operation_kind_t::enum_definition: return "enum_definition:" + operation.name;
    case overlay_operation_kind_t::define_function: prefix = "define_function"; break;
    case overlay_operation_kind_t::define_code: prefix = "define_code"; break;
    case overlay_operation_kind_t::define_data: prefix = "define_data"; break;
    case overlay_operation_kind_t::undefine: prefix = "undefine"; break;
    case overlay_operation_kind_t::stack_variable:
    case overlay_operation_kind_t::delete_stack_variable:
        return "stack_variable:" + address_key(operation.address) + ":" +
               std::to_string(operation.stack_offset) + ":" + operation.name;
    case overlay_operation_kind_t::type_application:
    case overlay_operation_kind_t::type_update:
        return "type_application:" + address_key(operation.address) + ":" +
               operation.variable + ":" + operation.name;
    case overlay_operation_kind_t::byte_patch:
    case overlay_operation_kind_t::assembly_patch:
    case overlay_operation_kind_t::integer_patch:
        prefix = "patch";
        break;
    case overlay_operation_kind_t::reanalysis:
        prefix = "reanalysis";
        break;
    }
    return prefix + ":" + address_key(operation.address);
}

bool removes_value(const overlay_operation_t& operation) {
    if (operation.remove)
        return true;
    if (operation.kind == overlay_operation_kind_t::comment ||
        operation.kind == overlay_operation_kind_t::comment_update)
        return operation.text.empty();
    if (operation.kind == overlay_operation_kind_t::name ||
        operation.kind == overlay_operation_kind_t::bookmark)
        return operation.name.empty();
    return false;
}

overlay_operation_t materialized_operation(overlay_operation_t operation) {
    if (operation.kind == overlay_operation_kind_t::comment_update)
        operation.kind = overlay_operation_kind_t::comment;
    else if (operation.kind == overlay_operation_kind_t::delete_stack_variable)
        operation.kind = overlay_operation_kind_t::stack_variable;
    else if (operation.kind == overlay_operation_kind_t::type_update)
        operation.kind = overlay_operation_kind_t::type_application;
    operation.remove = false;
    return operation;
}

bool contains_nul(const std::string& value) {
    return value.find('\0') != std::string::npos;
}

bool canonical_managed_payload(const overlay_operation_t& operation) noexcept {
    if (!operation.signature.empty() || !operation.bytes.empty() ||
        !operation.assembly.empty() || !operation.integer_type.empty() ||
        !operation.integer_value.empty() || operation.reanalysis_flags != 0 ||
        operation.stack_offset != 0)
        return false;
    switch (operation.kind) {
    case overlay_operation_kind_t::comment:
    case overlay_operation_kind_t::comment_update:
        return operation.name.empty() && operation.type.empty() &&
            operation.variable.empty();
    case overlay_operation_kind_t::name:
        return operation.text.empty() && operation.type.empty() &&
            operation.variable.empty();
    case overlay_operation_kind_t::type_application:
    case overlay_operation_kind_t::type_update:
        return operation.text.empty() &&
            (operation.name.empty() != operation.variable.empty());
    default:
        return false;
    }
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
        if (const auto normalized = workspace.normalized_image()) {
            std::uint64_t rva = operation.address.value;
            if (operation.address.space == address_space_id_t::virtual_address) {
                if (rva < normalized->image_base)
                    return workspace_result_t<std::uint64_t>::failure(make_workspace_error(
                        workspace_error_code_t::out_of_range,
                        "patch virtual address precedes the image base",
                        "overlay_journal.validate"));
                rva -= normalized->image_base;
            }
            if (operation.address.space == address_space_id_t::relative_virtual ||
                operation.address.space == address_space_id_t::virtual_address) {
                for (const auto& mapping : normalized->address_mappings) {
                    if (mapping.source_space != address_space_id_t::file_offset ||
                        mapping.target_space != address_space_id_t::relative_virtual ||
                        rva < mapping.target_start)
                        continue;
                    const auto delta = rva - mapping.target_start;
                    if (delta > mapping.size || size > mapping.size - delta)
                        continue;
                    std::uint64_t offset = 0;
                    if (checked_add_u64(mapping.source_start, delta, offset))
                        return workspace_result_t<std::uint64_t>::success(offset);
                }
            }
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
    const auto expected_mode = workspace.identity().architecture_mode();
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
    const auto normalized = workspace.normalized_image();
    if (!image && !normalized) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::provider_unavailable,
            "static virtual overlay address requires a parsed image",
            phase));
    }
    std::uint64_t rva = address.value;
    if (address.space == address_space_id_t::virtual_address) {
        if (image) {
            auto translated = image->va_to_rva(address.value);
            if (!translated)
                return workspace_result_t<void>::failure(translated.error());
            rva = translated.value();
        } else if (address.value < normalized->image_base) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::out_of_range,
                "overlay virtual address precedes the image base", phase));
        } else {
            rva = address.value - normalized->image_base;
        }
    }
    const std::uint64_t image_size = image ? image->image_size() : normalized->image_size;
    if (rva >= image_size) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::out_of_range,
            "overlay virtual address is outside the image",
            phase));
    }
    return workspace_result_t<void>::success();
}

std::optional<overlay_architecture_v9_t> overlay_architecture(
    architecture_id_t architecture) noexcept {
    switch (architecture) {
    case architecture_id_t::x86: return overlay_architecture_v9_t::x86;
    case architecture_id_t::x86_64: return overlay_architecture_v9_t::x86_64;
    case architecture_id_t::arm: return overlay_architecture_v9_t::arm;
    case architecture_id_t::aarch64:
    case architecture_id_t::arm64ec:
        return overlay_architecture_v9_t::arm64;
    case architecture_id_t::mips:
    case architecture_id_t::mips64:
        return overlay_architecture_v9_t::mips;
    case architecture_id_t::ppc:
    case architecture_id_t::ppc64:
        return overlay_architecture_v9_t::ppc;
    case architecture_id_t::riscv:
    case architecture_id_t::riscv32:
    case architecture_id_t::riscv64:
        return overlay_architecture_v9_t::riscv;
    case architecture_id_t::jvm_bytecode: return overlay_architecture_v9_t::jvm;
    case architecture_id_t::dalvik_bytecode: return overlay_architecture_v9_t::dalvik;
    case architecture_id_t::unknown: return std::nullopt;
    }
    return std::nullopt;
}

std::uint8_t overlay_address_width(const analysis_workspace_t& workspace) noexcept {
    if (const auto image = workspace.normalized_image()) {
        if (image->address_width_bits == 32 || image->address_width_bits == 64)
            return static_cast<std::uint8_t>(image->address_width_bits / 8);
    }
    switch (workspace.identity().architecture_mode()) {
    case architecture_mode_t::x86_64:
    case architecture_mode_t::aarch64:
    case architecture_mode_t::mips64:
    case architecture_mode_t::ppc64:
    case architecture_mode_t::riscv64:
        return 8;
    case architecture_mode_t::x86_16:
    case architecture_mode_t::x86_32:
    case architecture_mode_t::arm_a32:
    case architecture_mode_t::arm_thumb:
    case architecture_mode_t::mips32:
    case architecture_mode_t::ppc32:
    case architecture_mode_t::riscv32:
    case architecture_mode_t::jvm:
    case architecture_mode_t::dalvik:
        return 4;
    case architecture_mode_t::unknown:
        return 0;
    }
    return 0;
}

workspace_result_t<overlay_target_identity_v9_t> make_fixed_target_identity(
    const analysis_workspace_t& workspace) {
    const auto architecture = overlay_architecture(workspace.identity().architecture());
    overlay_target_identity_v9_t target;
    if (!architecture) {
        return workspace_result_t<overlay_target_identity_v9_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "workspace architecture cannot be represented by overlay v9",
            "overlay_journal.target"));
    }
    target.image_hash = workspace.identity().content_hash().bytes;
    target.provenance_hash = workspace.identity().load_profile_hash().bytes;
    target.image_base = workspace.identity().image_base();
    target.image_size = workspace.provider().size();
    if (const auto normalized = workspace.normalized_image()) {
        target.image_base = normalized->image_base;
        target.image_size = normalized->image_size;
    } else if (const auto image = workspace.image()) {
        target.image_size = image->image_size();
    }
    if (workspace.target_kind() == target_kind_t::live_snapshot && workspace.identity().module()) {
        target.image_base = workspace.identity().module()->base;
        target.image_size = workspace.identity().module()->size;
    }
    target.generation = workspace.generation();
    target.kind = workspace.target_kind() == target_kind_t::static_file
        ? overlay_target_kind_v9_t::static_image : overlay_target_kind_v9_t::live_image;
    target.architecture = *architecture;
    target.address_width = overlay_address_width(workspace);
    if (!target.valid()) {
        return workspace_result_t<overlay_target_identity_v9_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "workspace cannot produce a valid fixed overlay v9 target identity",
            "overlay_journal.target"));
    }
    return workspace_result_t<overlay_target_identity_v9_t>::success(target);
}

workspace_result_t<std::uint64_t> overlay_static_offset(
    const address_t& address, const analysis_workspace_t& workspace,
    const char* phase) {
    if (address.space == address_space_id_t::relative_virtual)
        return workspace_result_t<std::uint64_t>::success(address.value);
    const auto image = workspace.image();
    if (image && address.space == address_space_id_t::virtual_address)
        return image->va_to_rva(address.value);
    if (image && address.space == address_space_id_t::file_offset)
        return image->file_offset_to_rva(address.value, 1);
    if (const auto normalized = workspace.normalized_image()) {
        if (address.space == address_space_id_t::virtual_address &&
            address.value >= normalized->image_base &&
            address.value - normalized->image_base < normalized->image_size) {
            return workspace_result_t<std::uint64_t>::success(
                address.value - normalized->image_base);
        }
        if (address.space == address_space_id_t::file_offset) {
            for (const auto& mapping : normalized->address_mappings) {
                if (mapping.source_space != address_space_id_t::file_offset ||
                    mapping.target_space != address_space_id_t::relative_virtual ||
                    address.value < mapping.source_start ||
                    address.value - mapping.source_start >= mapping.size)
                    continue;
                std::uint64_t converted = 0;
                if (checked_add_u64(mapping.target_start,
                                    address.value - mapping.source_start, converted))
                    return workspace_result_t<std::uint64_t>::success(converted);
                break;
            }
        }
    }
    return workspace_result_t<std::uint64_t>::failure(make_workspace_error(
        workspace_error_code_t::unsupported_address_space,
        "overlay v9 requires a static address space", phase));
}

workspace_result_t<overlay_operation_v9_t> operation_to_v9(
    const overlay_operation_t& operation, const analysis_workspace_t& workspace,
    const overlay_target_identity_v9_t& target, const char* phase) {
    const auto ordinal = static_cast<std::uint8_t>(operation.kind);
    const auto kind = overlay_operation_kind_from_ordinal(ordinal);
    if (!kind) {
        return workspace_result_t<overlay_operation_v9_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "overlay operation kind cannot be adapted to v9", phase));
    }
    overlay_operation_v9_t result;
    result.kind = *kind;
    result.target_discriminator = operation.target_discriminator;
    result.managed_locator = operation.managed_locator;
    result.payload.name = operation.name;
    result.payload.text = operation.text;
    result.payload.type = operation.type;
    result.payload.variable = operation.variable;
    result.payload.signature = operation.signature;
    result.payload.assembly = operation.assembly;
    result.payload.integer_type = operation.integer_type;
    result.payload.integer_value = operation.integer_value;
    result.payload.bytes = operation.bytes;
    result.payload.reanalysis_flags = operation.reanalysis_flags;
    result.payload.stack_offset = operation.stack_offset;
    result.remove = removes_value(operation);
    if (operation.target_discriminator ==
        overlay_target_discriminator_v9_t::managed_entity)
        return workspace_result_t<overlay_operation_v9_t>::success(
            std::move(result));
    if (*kind == overlay_operation_kind_v9_t::type_declaration ||
        *kind == overlay_operation_kind_v9_t::enum_definition)
        return workspace_result_t<overlay_operation_v9_t>::success(std::move(result));
    auto start = overlay_static_offset(operation.address, workspace, phase);
    if (!start)
        return workspace_result_t<overlay_operation_v9_t>::failure(start.error());
    result.range.offset = start.value();
    if (operation.end) {
        if (operation.end->value <= operation.address.value) {
            return workspace_result_t<overlay_operation_v9_t>::failure(make_workspace_error(
                workspace_error_code_t::invalid_argument,
                "overlay v9 range is not increasing", phase));
        }
        result.range.size = operation.end->value - operation.address.value;
    } else if (!operation.bytes.empty()) {
        result.range.size = static_cast<std::uint64_t>(operation.bytes.size());
    } else {
        result.range.size = 1;
    }
    if (result.range.offset >= target.image_size ||
        result.range.size > target.image_size - result.range.offset) {
        return workspace_result_t<overlay_operation_v9_t>::failure(make_workspace_error(
            workspace_error_code_t::out_of_range,
            "overlay v9 range exceeds the fixed target", phase));
    }
    return workspace_result_t<overlay_operation_v9_t>::success(std::move(result));
}

workspace_result_t<overlay_operation_t> operation_from_v9(
    const overlay_operation_v9_t& operation, const analysis_workspace_t& workspace,
    const overlay_target_identity_v9_t& target) {
    const auto ordinal = static_cast<std::uint8_t>(operation.kind);
    if (!overlay_operation_kind_from_ordinal(ordinal)) {
        return workspace_result_t<overlay_operation_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "overlay v9 operation kind is invalid", "overlay_journal.adapter"));
    }
    overlay_operation_t result;
    result.kind = static_cast<overlay_operation_kind_t>(ordinal);
    result.target_discriminator = operation.target_discriminator;
    result.managed_locator = operation.managed_locator;
    result.name = operation.payload.name;
    result.text = operation.payload.text;
    result.type = operation.payload.type;
    result.variable = operation.payload.variable;
    result.signature = operation.payload.signature;
    result.assembly = operation.payload.assembly;
    result.integer_type = operation.payload.integer_type;
    result.integer_value = operation.payload.integer_value;
    result.bytes = operation.payload.bytes;
    result.reanalysis_flags = operation.payload.reanalysis_flags;
    result.stack_offset = operation.payload.stack_offset;
    result.remove = operation.remove;
    if (operation.target_discriminator ==
        overlay_target_discriminator_v9_t::managed_entity) {
        if (operation.range.offset != 0 || operation.range.size != 0 ||
            !operation.managed_locator) {
            return workspace_result_t<overlay_operation_t>::failure(
                make_workspace_error(
                    workspace_error_code_t::invalid_argument,
                    "managed overlay v9 operation contains an address range",
                    "overlay_journal.adapter"));
        }
        return workspace_result_t<overlay_operation_t>::success(
            std::move(result));
    }
    result.address.space = address_space_id_t::relative_virtual;
    result.address.architecture = workspace.identity().architecture();
    result.address.mode = workspace.identity().architecture_mode();
    if (operation.kind == overlay_operation_kind_v9_t::type_declaration ||
        operation.kind == overlay_operation_kind_v9_t::enum_definition) {
        if (operation.range.offset != 0 || operation.range.size != 0) {
            return workspace_result_t<overlay_operation_t>::failure(make_workspace_error(
                workspace_error_code_t::invalid_argument,
                "global overlay v9 operation contains a range", "overlay_journal.adapter"));
        }
        return workspace_result_t<overlay_operation_t>::success(std::move(result));
    }
    if (operation.range.size == 0 || operation.range.offset >= target.image_size ||
        operation.range.size > target.image_size - operation.range.offset) {
        return workspace_result_t<overlay_operation_t>::failure(make_workspace_error(
            workspace_error_code_t::out_of_range,
            "overlay v9 operation range exceeds the fixed target",
            "overlay_journal.adapter"));
    }
    result.address.value = operation.range.offset;
    auto end = result.address;
    if (!checked_add_u64(operation.range.offset, operation.range.size, end.value)) {
        return workspace_result_t<overlay_operation_t>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "overlay v9 operation range overflows", "overlay_journal.adapter"));
    }
    result.end = end;
    return workspace_result_t<overlay_operation_t>::success(std::move(result));
}

workspace_error_t overlay_apply_error(overlay_apply_code_v9_t code, const char* phase) {
    workspace_error_code_t mapped = workspace_error_code_t::integrity_failure;
    switch (code) {
    case overlay_apply_code_v9_t::ok: mapped = workspace_error_code_t::none; break;
    case overlay_apply_code_v9_t::invalid_target:
    case overlay_apply_code_v9_t::static_target_required:
        mapped = workspace_error_code_t::target_conflict;
        break;
    case overlay_apply_code_v9_t::stale_generation:
        mapped = workspace_error_code_t::stale_generation;
        break;
    case overlay_apply_code_v9_t::revision_conflict:
    case overlay_apply_code_v9_t::duplicate_entity:
        mapped = workspace_error_code_t::revision_conflict;
        break;
    case overlay_apply_code_v9_t::revision_overflow:
    case overlay_apply_code_v9_t::transaction_overflow:
    case overlay_apply_code_v9_t::history_overflow:
        mapped = workspace_error_code_t::range_overflow;
        break;
    case overlay_apply_code_v9_t::invalid_operation:
        mapped = workspace_error_code_t::invalid_argument;
        break;
    case overlay_apply_code_v9_t::limit_exceeded:
        mapped = workspace_error_code_t::limit_exceeded;
        break;
    case overlay_apply_code_v9_t::no_undo:
    case overlay_apply_code_v9_t::no_redo:
        mapped = workspace_error_code_t::target_not_found;
        break;
    case overlay_apply_code_v9_t::state_not_initialized:
    case overlay_apply_code_v9_t::state_already_initialized:
        mapped = workspace_error_code_t::integrity_failure;
        break;
    case overlay_apply_code_v9_t::storage_failure:
        mapped = workspace_error_code_t::persistence_failure;
        break;
    }
    auto error = make_workspace_error(mapped, "overlay v9 apply engine rejected the operation", phase);
    error.details.emplace_back("overlay_apply_code", std::to_string(static_cast<unsigned>(code)));
    return error;
}

workspace_result_t<overlay_static_state_v9_t> make_v9_preflight_state(
    const overlay_snapshot_t& snapshot, const analysis_workspace_t& workspace,
    const overlay_target_identity_v9_t& target) {
    overlay_static_state_v9_t state;
    const auto initialized = overlay_apply_engine_v9_t::initialize(state, target);
    if (!initialized.ok()) {
        return workspace_result_t<overlay_static_state_v9_t>::failure(
            overlay_apply_error(initialized.code, "overlay_journal.preflight"));
    }
    state.revision = snapshot.revision;
    state.history_epoch = snapshot.history_epoch == 0 ? 1 : snapshot.history_epoch;
    for (const auto& item : snapshot.items) {
        auto operation = operation_to_v9(item.second, workspace, target,
                                         "overlay_journal.preflight");
        if (!operation)
            return workspace_result_t<overlay_static_state_v9_t>::failure(operation.error());
        operation.value().remove = false;
        const auto key = overlay_entity_key_for_operation_v9(operation.value());
        if (!state.items.emplace(key, operation.value().payload).second) {
            return workspace_result_t<overlay_static_state_v9_t>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "persisted overlay items alias the same v9 entity",
                "overlay_journal.preflight"));
        }
    }
    return workspace_result_t<overlay_static_state_v9_t>::success(std::move(state));
}

bool current_managed_locator_matches_workspace(
    const overlay_managed_entity_locator_v9_t& locator,
    const analysis_workspace_t& workspace) noexcept {
    try {
        const auto publication = workspace.analysis_publication();
        if (!publication || !publication->coherent_with(workspace.identity()) ||
            !publication->managed_artifacts ||
            publication->generation != workspace.generation() ||
            publication->analysis_revision != workspace.analysis_revision() ||
            publication->overlay_revision != workspace.overlay_revision() ||
            publication->managed_artifacts->binary_id.bytes !=
                locator.workspace_id ||
            publication->managed_artifacts->load_profile_hash !=
                workspace.identity().load_profile_hash() ||
            publication->managed_artifacts->provider_size !=
                locator.provider_size)
            return false;
        const auto decoded = deserialize_decompiler_entity_key(
            locator.serialized_entity);
        if (!decoded.valid() || !decoded.value)
            return false;
        bool matched = false;
        for (const auto& method : publication->managed_artifacts->methods()) {
            if (!method.has_body || method.entity != *decoded.value ||
                method.artifact_index >=
                    publication->managed_artifacts->artifacts().size())
                continue;
            const auto& artifact = publication->managed_artifacts->artifacts()[
                method.artifact_index];
            if (artifact.artifact_hash.bytes != locator.artifact_hash)
                continue;
            if (matched)
                return false;
            matched = true;
        }
        return matched;
    } catch (...) {
        return false;
    }
}

workspace_result_t<void> validate_operation(
    const overlay_operation_t& operation, const overlay_limits_t& limits,
    const analysis_workspace_t& workspace, std::size_t& total_patch_bytes,
    bool allow_historical_generation = false) {
    const unsigned kind_value = static_cast<unsigned>(operation.kind);
    if (kind_value > static_cast<unsigned>(overlay_operation_kind_t::reanalysis)) {
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
    const bool managed = operation.target_discriminator ==
        overlay_target_discriminator_v9_t::managed_entity;
    if (operation.target_discriminator ==
        overlay_target_discriminator_v9_t::native_address) {
        if (operation.managed_locator) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::invalid_argument,
                "native overlay operation contains a managed locator",
                "overlay_journal.validate"));
        }
    } else if (managed) {
        const auto managed_kind = managed_overlay_operation_kind_v9(
            static_cast<overlay_operation_kind_v9_t>(kind_value));
        if (!operation.managed_locator || !operation.managed_locator->valid() ||
            operation.managed_locator->workspace_id !=
                workspace.identity().binary_id().bytes ||
            operation.managed_locator->provider_hash !=
                workspace.identity().content_hash().bytes ||
            operation.managed_locator->provider_size != workspace.provider().size() ||
            operation.managed_locator->generation == 0 ||
            (allow_historical_generation
                 ? operation.managed_locator->generation > workspace.generation()
                 : operation.managed_locator->generation != workspace.generation()) ||
            (!allow_historical_generation &&
             !current_managed_locator_matches_workspace(
                 *operation.managed_locator, workspace)) ||
            workspace.target_kind() != target_kind_t::static_file ||
            !managed_kind || !canonical_managed_payload(operation) ||
            operation.end) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::invalid_argument,
                "managed overlay locator, generation, operation, or payload is invalid",
                "overlay_journal.validate"));
        }
        if (operation.managed_locator->serialized_entity.size() >
            limits.max_managed_entity_bytes) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "managed overlay entity exceeds configured limit",
                "overlay_journal.validate"));
        }
    } else {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "overlay target discriminator is invalid",
            "overlay_journal.validate"));
    }
    if (!managed &&
        operation.kind != overlay_operation_kind_t::type_declaration &&
        operation.kind != overlay_operation_kind_t::enum_definition) {
        auto address_result = validate_workspace_address(
            operation.address, workspace, "overlay_journal.validate");
        if (!address_result)
            return address_result;
    }
    if (!managed && operation.end) {
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
    const bool removal = removes_value(operation);
    if (operation.kind == overlay_operation_kind_t::type_declaration &&
        (operation.name.empty() || (!removal && operation.type.empty()))) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "type declaration requires a name and declaration text",
            "overlay_journal.validate"));
    }
    if (operation.kind == overlay_operation_kind_t::enum_definition &&
        (operation.name.empty() || (!removal && operation.type.empty()))) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "enum definition requires a name and declaration text",
            "overlay_journal.validate"));
    }
    if ((operation.kind == overlay_operation_kind_t::stack_variable ||
         operation.kind == overlay_operation_kind_t::delete_stack_variable) &&
        operation.name.empty()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "stack variable operation requires a name", "overlay_journal.validate"));
    }
    if (operation.kind == overlay_operation_kind_t::stack_variable &&
        !removal && operation.type.empty()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "stack variable declaration requires a type", "overlay_journal.validate"));
    }
    if ((operation.kind == overlay_operation_kind_t::type_application ||
         operation.kind == overlay_operation_kind_t::type_update) &&
        (operation.name.empty() && operation.variable.empty())) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "type operation requires an entity name or variable",
            "overlay_journal.validate"));
    }
    if ((operation.kind == overlay_operation_kind_t::type_application ||
         operation.kind == overlay_operation_kind_t::type_update) &&
        !removal && operation.type.empty()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "type operation requires a type",
            "overlay_journal.validate"));
    }
    if (operation.kind == overlay_operation_kind_t::comment_update &&
        !removal && operation.text.empty()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "comment update requires text",
            "overlay_journal.validate"));
    }
    const bool patch = operation.kind == overlay_operation_kind_t::byte_patch ||
                       operation.kind == overlay_operation_kind_t::assembly_patch ||
                       operation.kind == overlay_operation_kind_t::integer_patch;
    if (patch && !removal) {
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

workspace_result_t<void> bind_operation_target(
    overlay_statement_t& statement, int first,
    const overlay_operation_t& operation) {
    auto result = statement.bind_int(
        first, static_cast<std::int64_t>(operation.target_discriminator));
    if (!result)
        return result;
    if (operation.target_discriminator ==
        overlay_target_discriminator_v9_t::native_address) {
        result = bind_operation_address(statement, first + 1, operation.address);
        if (!result)
            return result;
        for (int index = first + 5; index <= first + 11; ++index) {
            result = statement.bind_null(index);
            if (!result)
                return result;
        }
        return result;
    }
    if (operation.target_discriminator !=
            overlay_target_discriminator_v9_t::managed_entity ||
        !operation.managed_locator) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "overlay operation target cannot be persisted",
            "overlay_journal.persistence"));
    }
    for (int index = first + 1; index <= first + 4; ++index) {
        result = statement.bind_null(index);
        if (!result)
            return result;
    }
    const auto& locator = *operation.managed_locator;
    result = statement.bind_blob(first + 5, locator.workspace_id.data(),
                                 locator.workspace_id.size());
    if (!result) return result;
    result = statement.bind_blob(first + 6, locator.provider_hash.data(),
                                 locator.provider_hash.size());
    if (!result) return result;
    result = statement.bind_uint(first + 7, locator.provider_size);
    if (!result) return result;
    result = statement.bind_blob(first + 8, locator.artifact_hash.data(),
                                 locator.artifact_hash.size());
    if (!result) return result;
    result = statement.bind_uint(first + 9, locator.generation);
    if (!result) return result;
    result = statement.bind_blob(first + 10, locator.entity_hash.data(),
                                 locator.entity_hash.size());
    if (!result) return result;
    return statement.bind_blob(first + 11, locator.serialized_entity.data(),
                               locator.serialized_entity.size());
}

bool overlay_blob_equals(sqlite3_stmt* statement, int column,
                         const void* expected, std::size_t expected_size) noexcept {
    if (sqlite3_column_type(statement, column) != SQLITE_BLOB ||
        sqlite3_column_bytes(statement, column) !=
            static_cast<int>(expected_size))
        return false;
    const void* value = sqlite3_column_blob(statement, column);
    return value && std::memcmp(value, expected, expected_size) == 0;
}

bool operation_target_matches_columns(
    sqlite3_stmt* statement, int first,
    const overlay_operation_t& operation,
    std::uint64_t maximum_managed_generation,
    bool allow_managed_generation_mismatch = false) noexcept {
    if (sqlite3_column_type(statement, first) != SQLITE_INTEGER ||
        sqlite3_column_int(statement, first) !=
            static_cast<int>(operation.target_discriminator))
        return false;
    if (operation.target_discriminator ==
        overlay_target_discriminator_v9_t::native_address) {
        if (operation.managed_locator ||
            sqlite3_column_type(statement, first + 1) != SQLITE_INTEGER ||
            sqlite3_column_type(statement, first + 2) != SQLITE_INTEGER ||
            sqlite3_column_type(statement, first + 3) != SQLITE_INTEGER ||
            sqlite3_column_type(statement, first + 4) != SQLITE_INTEGER ||
            sqlite3_column_int(statement, first + 1) !=
                static_cast<int>(operation.address.space) ||
            static_cast<std::uint64_t>(sqlite3_column_int64(
                statement, first + 2)) != operation.address.value ||
            sqlite3_column_int(statement, first + 3) !=
                static_cast<int>(operation.address.architecture) ||
            sqlite3_column_int(statement, first + 4) !=
                static_cast<int>(operation.address.mode))
            return false;
        for (int index = first + 5; index <= first + 11; ++index) {
            if (sqlite3_column_type(statement, index) != SQLITE_NULL)
                return false;
        }
        return true;
    }
    if (operation.target_discriminator !=
            overlay_target_discriminator_v9_t::managed_entity ||
        !operation.managed_locator)
        return false;
    for (int index = first + 1; index <= first + 4; ++index) {
        if (sqlite3_column_type(statement, index) != SQLITE_NULL)
            return false;
    }
    const auto& locator = *operation.managed_locator;
    if (sqlite3_column_type(statement, first + 7) != SQLITE_INTEGER ||
        sqlite3_column_type(statement, first + 9) != SQLITE_INTEGER)
        return false;
    const auto provider_size = static_cast<std::uint64_t>(
        sqlite3_column_int64(statement, first + 7));
    const auto generation = static_cast<std::uint64_t>(
        sqlite3_column_int64(statement, first + 9));
    if (provider_size == 0 || provider_size != locator.provider_size ||
        generation == 0 || generation > maximum_managed_generation ||
        (allow_managed_generation_mismatch
             ? generation < locator.generation
             : generation != locator.generation))
        return false;
    return overlay_blob_equals(statement, first + 5,
                               locator.workspace_id.data(),
                               locator.workspace_id.size()) &&
        overlay_blob_equals(statement, first + 6,
                            locator.provider_hash.data(),
                            locator.provider_hash.size()) &&
        overlay_blob_equals(statement, first + 8,
                            locator.artifact_hash.data(),
                            locator.artifact_hash.size()) &&
        overlay_blob_equals(statement, first + 10,
                            locator.entity_hash.data(),
                            locator.entity_hash.size()) &&
        overlay_blob_equals(statement, first + 11,
                            locator.serialized_entity.data(),
                            locator.serialized_entity.size());
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
    if (!ticket.accepted || !ticket.completion.valid()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::persistence_failure,
            "persistence queue returned an invalid completion ticket",
            "overlay_journal"));
    }
    std::optional<std::chrono::steady_clock::time_point> resolution_deadline;
    for (;;) {
        if (ticket.completion.wait_for(std::chrono::milliseconds(10)) == std::future_status::ready) {
            try {
                const auto& result = ticket.completion.get();
                if (result)
                    return workspace_result_t<void>::success();
                return workspace_result_t<void>::failure(result.error());
            } catch (...) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::persistence_failure,
                    "persistence completion raised an exception",
                    "overlay_journal"));
            }
        }
        if (cancel.stop_requested() && !resolution_deadline)
            resolution_deadline = std::chrono::steady_clock::now() +
                std::chrono::seconds(2);
        if (resolution_deadline &&
            std::chrono::steady_clock::now() >= *resolution_deadline) {
            auto error = make_workspace_error(
                cancel.deadline_exceeded()
                    ? workspace_error_code_t::deadline_exceeded
                    : workspace_error_code_t::cancelled,
                "persistence cancellation did not reach a terminal commit state within the resolution bound",
                "overlay_journal");
            error.deadline = cancel.deadline_exceeded();
            error.cancellation = !error.deadline;
            error.details.emplace_back("commit_state", "unresolved");
            error.details.emplace_back("resolution_timeout_ms", "2000");
            return workspace_result_t<void>::failure(std::move(error));
        }
    }
}

workspace_result_t<std::shared_ptr<const workspace_persistence_candidate_t>>
stage_projected_candidate(
    const std::shared_ptr<workspace_database_t>& database,
    const std::shared_ptr<const analysis_snapshot_t>& snapshot,
    const std::shared_ptr<search_index_t>& index,
    const std::shared_ptr<const managed_artifact_publication_t>& managed_publication,
    const cancellation_token_t& cancel) {
    if (!database || !snapshot)
        return workspace_result_t<std::shared_ptr<const workspace_persistence_candidate_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "projected persistence candidate is incomplete",
                                 "overlay_journal.persistence"));
    const auto& versions = database->options().versions;
    const std::string settings = json{
        {"analysis_settings_hash", versions.analysis_settings_hash},
        {"engine_version", versions.engine_version},
        {"specification_version", versions.specification_version},
        {"source", "overlay_projection"}}.dump();
    persistence_ticket_t ticket;
    if (index) {
        persisted_search_products_t products;
        products.generation = snapshot->generation;
        products.analysis_revision = snapshot->analysis_revision;
        products.overlay_revision = snapshot->overlay_revision;
        products.live_index = index;
        ticket = database->persist_snapshot(
            snapshot, std::move(products), managed_publication,
            settings, "{}", cancel);
    } else {
        ticket = database->persist_snapshot(
            snapshot, managed_publication, settings, "{}", cancel);
    }
    auto waited = wait_ticket(ticket, cancel);
    if (!waited) {
        if (ticket.snapshot_candidate) {
            auto discarded = ticket.snapshot_candidate->discard();
            if (!discarded) {
                auto error = waited.error();
                error.details.emplace_back(
                    "candidate_discard_error", discarded.error().stable_code());
                return workspace_result_t<std::shared_ptr<const workspace_persistence_candidate_t>>::failure(
                    std::move(error));
            }
        }
        return workspace_result_t<std::shared_ptr<const workspace_persistence_candidate_t>>::failure(
            waited.error());
    }
    if (!ticket.snapshot_candidate ||
        ticket.snapshot_candidate->generation() != snapshot->generation ||
        ticket.snapshot_candidate->analysis_revision() != snapshot->analysis_revision ||
        ticket.snapshot_candidate->overlay_revision() != snapshot->overlay_revision) {
        auto error = make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "projected persistence candidate identity is inconsistent",
            "overlay_journal.persistence");
        if (ticket.snapshot_candidate) {
            auto discarded = ticket.snapshot_candidate->discard();
            if (!discarded)
                error.details.emplace_back(
                    "candidate_discard_error", discarded.error().stable_code());
        }
        return workspace_result_t<std::shared_ptr<const workspace_persistence_candidate_t>>::failure(
            std::move(error));
    }
    return workspace_result_t<std::shared_ptr<const workspace_persistence_candidate_t>>::success(
        ticket.snapshot_candidate);
}

workspace_result_t<void> promote_projected_candidate(
    sqlite3* writer,
    const workspace_persistence_candidate_t& candidate,
    const analysis_snapshot_t& snapshot,
    const cancellation_token_t& token,
    const char* phase) {
    overlay_statement_t state;
    auto current = state.prepare(writer,
        "SELECT active_slot,candidate_slot,candidate_token,candidate_generation,candidate_analysis_revision,candidate_overlay_revision,candidate_ready FROM workspace_commit_state WHERE singleton=1",
        phase);
    if (!current)
        return current;
    const int status = sqlite3_step(state.get());
    if (status != SQLITE_ROW || sqlite3_column_type(state.get(), 1) == SQLITE_NULL ||
        sqlite3_column_type(state.get(), 2) == SQLITE_NULL ||
        sqlite3_column_type(state.get(), 3) == SQLITE_NULL ||
        sqlite3_column_type(state.get(), 4) == SQLITE_NULL ||
        sqlite3_column_type(state.get(), 5) == SQLITE_NULL ||
        sqlite3_column_int(state.get(), 6) != 1) {
        auto error = make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "projected persistence candidate is no longer pending", phase);
        error.sqlite_status = status;
        return workspace_result_t<void>::failure(std::move(error));
    }
    const auto active_slot = sqlite3_column_int(state.get(), 0);
    const auto candidate_slot = sqlite3_column_int(state.get(), 1);
    if ((active_slot != 0 && active_slot != 1) ||
        (candidate_slot != 0 && candidate_slot != 1) ||
        active_slot == candidate_slot ||
        overlay_column_text(state.get(), 2) != candidate.token() ||
        static_cast<std::uint64_t>(sqlite3_column_int64(state.get(), 3)) !=
            candidate.generation() ||
        static_cast<std::uint64_t>(sqlite3_column_int64(state.get(), 4)) !=
            candidate.analysis_revision() ||
        static_cast<std::uint64_t>(sqlite3_column_int64(state.get(), 5)) !=
            candidate.overlay_revision())
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "projected persistence candidate changed before overlay commit",
            phase));
    const std::string state_table = candidate_slot == 0
        ? "analysis_state" : "alternate_analysis_state";
    overlay_statement_t candidate_state;
    const auto candidate_sql =
        "SELECT generation,analysis_revision,overlay_revision,commit_token FROM " +
        state_table + " WHERE singleton=1";
    current = candidate_state.prepare(writer, candidate_sql.c_str(), phase);
    if (!current)
        return current;
    const int candidate_status = sqlite3_step(candidate_state.get());
    if (candidate_status != SQLITE_ROW ||
        static_cast<std::uint64_t>(sqlite3_column_int64(candidate_state.get(), 0)) !=
            candidate.generation() ||
        static_cast<std::uint64_t>(sqlite3_column_int64(candidate_state.get(), 1)) !=
            candidate.analysis_revision() ||
        static_cast<std::uint64_t>(sqlite3_column_int64(candidate_state.get(), 2)) !=
            candidate.overlay_revision() ||
        overlay_column_text(candidate_state.get(), 3) != candidate.token())
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "projected candidate fact slot is inconsistent", phase));
    if (candidate.packed_generation_required()) {
        auto packed = read_packed_generation(
            writer, candidate.generation(), false,
            [&token] { return token.stop_requested(); });
        if (!packed)
            return workspace_result_t<void>::failure(packed.error());
        auto expected_manifest = encode_packed_baseline_manifest(
            snapshot, candidate.token(), token);
        if (!expected_manifest)
            return workspace_result_t<void>::failure(
                expected_manifest.error());
        if (!packed.value() || packed.value()->committed ||
            packed.value()->analysis_revision !=
                candidate.analysis_revision() ||
            packed.value()->overlay_revision != candidate.overlay_revision() ||
            packed.value()->payload_blob != expected_manifest.value())
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "projected packed candidate identity is inconsistent",
                phase));
        auto published = publish_packed_generation(
            writer, candidate.generation(),
            [&token] { return token.stop_requested(); });
        if (!published)
            return published;
    }
    overlay_statement_t promote;
    current = promote.prepare(writer,
        "UPDATE workspace_commit_state SET active_slot=?1,committed_token=?2,committed_generation=?3,committed_analysis_revision=?4,committed_overlay_revision=?5,candidate_slot=NULL,candidate_token=NULL,candidate_generation=NULL,candidate_analysis_revision=NULL,candidate_overlay_revision=NULL,candidate_ready=0,updated_utc_ms=?6 WHERE singleton=1 AND active_slot=?7 AND candidate_slot=?1 AND candidate_ready=1 AND candidate_token=?2",
        phase);
    if (!current)
        return current;
    current = promote.bind_int(1, candidate_slot); if (!current) return current;
    current = promote.bind_text(2, candidate.token()); if (!current) return current;
    current = promote.bind_uint(3, candidate.generation()); if (!current) return current;
    current = promote.bind_uint(4, candidate.analysis_revision()); if (!current) return current;
    current = promote.bind_uint(5, candidate.overlay_revision()); if (!current) return current;
    current = promote.bind_uint(6, overlay_utc_ms()); if (!current) return current;
    current = promote.bind_int(7, active_slot); if (!current) return current;
    current = promote.step_done();
    if (!current)
        return current;
    if (sqlite3_changes(writer) != 1)
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "projected persistence candidate was not promoted", phase));
    return workspace_result_t<void>::success();
}

overlay_apply_limits_v9_t projection_limits(const overlay_limits_t& limits) {
    overlay_apply_limits_v9_t result;
    result.max_operations_per_transaction = limits.max_operations;
    result.max_text_bytes = (std::max)(limits.max_comment_bytes,
        (std::max)(limits.max_name_bytes, limits.max_assembly_bytes));
    result.max_type_bytes = limits.max_type_bytes;
    result.max_patch_bytes_per_operation = limits.max_patch_bytes_per_item;
    result.max_patch_bytes_per_transaction = limits.max_patch_bytes_per_transaction;
    result.max_managed_entity_bytes = limits.max_managed_entity_bytes;
    return result;
}

workspace_error_t projection_error(const projection_result_t& result,
                                   const char* phase) {
    workspace_error_code_t code = workspace_error_code_t::integrity_failure;
    switch (result.code) {
    case projection_code_t::ok:
        code = workspace_error_code_t::none;
        break;
    case projection_code_t::invalid_target:
        code = workspace_error_code_t::target_conflict;
        break;
    case projection_code_t::stale_generation:
        code = workspace_error_code_t::stale_generation;
        break;
    case projection_code_t::conflict_detected:
    case projection_code_t::revision_conflict:
        code = workspace_error_code_t::revision_conflict;
        break;
    case projection_code_t::empty_projection:
    case projection_code_t::range_out_of_bounds:
    case projection_code_t::apply_failure:
    case projection_code_t::invalid_patch_provenance:
    case projection_code_t::invalid_publication:
        code = workspace_error_code_t::invalid_argument;
        break;
    case projection_code_t::transaction_overflow:
        code = workspace_error_code_t::range_overflow;
        break;
    case projection_code_t::publication_failed:
    case projection_code_t::finalizer_failed:
        code = workspace_error_code_t::persistence_failure;
        break;
    case projection_code_t::state_not_initialized:
        code = workspace_error_code_t::integrity_failure;
        break;
    }
    auto error = make_workspace_error(
        code, result.detail.empty() ? "overlay projection failed" : result.detail,
        phase);
    error.details.emplace_back(
        "projection_code", std::to_string(static_cast<unsigned>(result.code)));
    return error;
}

workspace_error_t projection_finalize_error(
    const projection_finalize_result_t& result,
    const char* phase) {
    projection_result_t projected;
    projected.code = result.code;
    projected.detail = result.detail;
    auto error = projection_error(projected, phase);
    if (!result.invalidation.detail.empty())
        error.details.emplace_back(
            "invalidation_detail", result.invalidation.detail);
    error.details.emplace_back(
        "invalidation_code",
        std::to_string(static_cast<unsigned>(result.invalidation.code)));
    return error;
}

struct overlay_provider_mapping_t final {
    std::uint64_t source_start = 0;
    std::uint64_t target_start = 0;
    std::uint64_t size = 0;
};

class overlay_generation_provider_t final : public byte_provider_t {
public:
    overlay_generation_provider_t(
        std::shared_ptr<const byte_provider_t> storage,
        std::optional<provider_member_metadata_t> member,
        std::string normalized_source)
        : storage_(std::move(storage)), identity_(storage_->identity()) {
        identity_.member = std::move(member);
        identity_.normalized_source = std::move(normalized_source);
    }

    const byte_provider_identity_t& identity() const noexcept override {
        return identity_;
    }

    std::uint64_t size() const noexcept override {
        return storage_->size();
    }

    std::uint64_t maximum_contiguous_lease(
        std::uint64_t offset) const noexcept override {
        return storage_->maximum_contiguous_lease(offset);
    }

    workspace_result_t<byte_view_t> lease(
        std::uint64_t offset, std::uint64_t size,
        const cancellation_token_t& cancel) const override {
        return storage_->lease(offset, size, cancel);
    }

private:
    std::shared_ptr<const byte_provider_t> storage_;
    byte_provider_identity_t identity_;
};

std::string overlay_provider_source(
    const analysis_workspace_t& workspace,
    const projection_result_t& prepared) {
    return "overlay://" + workspace.identity().binary_id().to_hex() +
        "/generation/" + std::to_string(prepared.new_generation) +
        "/revision/" + std::to_string(prepared.revision);
}

workspace_result_t<std::vector<overlay_provider_mapping_t>>
overlay_provider_mappings(
    const analysis_workspace_t& workspace,
    std::uint64_t projected_size) {
    const auto normalized = workspace.normalized_image();
    if (!normalized || projected_size != normalized->image_size)
        return workspace_result_t<std::vector<overlay_provider_mapping_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                                 "overlay projection has no matching normalized image",
                                 "overlay_journal.provider"));
    const auto source_size = workspace.source_provider().size();
    std::vector<overlay_provider_mapping_t> mappings;
    try {
        mappings.reserve(normalized->address_mappings.size() + 1);
        for (const auto& mapping : normalized->address_mappings) {
            if (mapping.size == 0)
                continue;
            if (mapping.source_space == address_space_id_t::file_offset &&
                mapping.target_space == address_space_id_t::relative_virtual) {
                mappings.push_back(
                    {mapping.source_start, mapping.target_start, mapping.size});
            } else if (
                mapping.source_space == address_space_id_t::relative_virtual &&
                mapping.target_space == address_space_id_t::file_offset) {
                mappings.push_back(
                    {mapping.target_start, mapping.source_start, mapping.size});
            }
        }
        if (mappings.empty()) {
            if (normalized->header_size != 0)
                mappings.push_back({0, 0, normalized->header_size});
            const auto append_regions = [&](const auto& regions) {
                for (const auto& region : regions) {
                    if (region.file_size != 0)
                        mappings.push_back({region.file_offset,
                                            region.virtual_address,
                                            region.file_size});
                }
            };
            if (normalized->sections.empty())
                append_regions(normalized->segments);
            else
                append_regions(normalized->sections);
        }
        if (mappings.empty() && source_size >= projected_size)
            mappings.push_back({0, 0, projected_size});
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::vector<overlay_provider_mapping_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "overlay provider mapping allocation failed",
                                 "overlay_journal.provider"));
    }
    if (mappings.empty())
        return workspace_result_t<std::vector<overlay_provider_mapping_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                                 "overlay image has no provider-backed ranges",
                                 "overlay_journal.provider"));
    for (const auto& mapping : mappings) {
        if (mapping.source_start > source_size ||
            mapping.size > source_size - mapping.source_start ||
            mapping.target_start > projected_size ||
            mapping.size > projected_size - mapping.target_start)
            return workspace_result_t<std::vector<overlay_provider_mapping_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "overlay provider mapping exceeds image bounds",
                                     "overlay_journal.provider"));
    }
    std::sort(mappings.begin(), mappings.end(),
        [](const auto& lhs, const auto& rhs) {
            return std::tie(lhs.source_start, lhs.target_start, lhs.size) <
                   std::tie(rhs.source_start, rhs.target_start, rhs.size);
        });
    for (std::size_t index = 1; index < mappings.size(); ++index) {
        const auto previous_end =
            mappings[index - 1].source_start + mappings[index - 1].size;
        if (mappings[index].source_start < previous_end)
            return workspace_result_t<std::vector<overlay_provider_mapping_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "overlay provider mappings overlap in source space",
                                     "overlay_journal.provider"));
    }
    auto target_order = mappings;
    std::sort(target_order.begin(), target_order.end(),
        [](const auto& lhs, const auto& rhs) {
            return std::tie(lhs.target_start, lhs.source_start, lhs.size) <
                   std::tie(rhs.target_start, rhs.source_start, rhs.size);
        });
    for (std::size_t index = 1; index < target_order.size(); ++index) {
        const auto previous_end =
            target_order[index - 1].target_start + target_order[index - 1].size;
        if (target_order[index].target_start < previous_end)
            return workspace_result_t<std::vector<overlay_provider_mapping_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "overlay provider mappings overlap in image space",
                                     "overlay_journal.provider"));
    }
    return workspace_result_t<std::vector<overlay_provider_mapping_t>>::success(
        std::move(mappings));
}

bool overlay_range_is_provider_backed(
    const overlay_static_range_v9_t& range,
    const std::vector<overlay_provider_mapping_t>& target_order) noexcept {
    if (range.size == 0)
        return false;
    const auto range_end = range.offset + range.size;
    std::uint64_t cursor = range.offset;
    for (const auto& mapping : target_order) {
        const auto mapping_end = mapping.target_start + mapping.size;
        if (mapping_end <= cursor)
            continue;
        if (mapping.target_start > cursor)
            return false;
        cursor = (std::min)(range_end, mapping_end);
        if (cursor == range_end)
            return true;
    }
    return false;
}

workspace_result_t<std::shared_ptr<const byte_provider_t>>
materialize_projected_provider(
    const analysis_workspace_t& workspace,
    const projection_result_t& prepared,
    const cancellation_token_t& cancel) {
    auto binding = workspace.verify_provider_binding();
    if (!binding)
        return workspace_result_t<std::shared_ptr<const byte_provider_t>>::failure(
            binding.error());
    if (!prepared.projected_state || prepared.projected_size == 0)
        return workspace_result_t<std::shared_ptr<const byte_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "projected overlay metadata is unavailable",
                                 "overlay_journal.provider"));
    auto mappings = overlay_provider_mappings(
        workspace, prepared.projected_size);
    if (!mappings)
        return workspace_result_t<std::shared_ptr<const byte_provider_t>>::failure(
            mappings.error());
    auto target_order = mappings.value();
    std::sort(target_order.begin(), target_order.end(),
        [](const auto& lhs, const auto& rhs) {
            return std::tie(lhs.target_start, lhs.source_start, lhs.size) <
                   std::tie(rhs.target_start, rhs.source_start, rhs.size);
        });
    struct patch_segment_t final {
        std::uint64_t source_offset = 0;
        std::uint64_t size = 0;
        const std::vector<std::uint8_t>* bytes = nullptr;
        std::uint64_t payload_offset = 0;
    };
    std::vector<patch_segment_t> patches;
    for (const auto& item : prepared.projected_state->items) {
        const auto kind = overlay_operation_kind_for_item_v9(
            item.first, item.second);
        if (!kind)
            return workspace_result_t<std::shared_ptr<const byte_provider_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "projected overlay item has no operation kind",
                                     "overlay_journal.provider"));
        if (*kind != overlay_operation_kind_v9_t::byte_patch &&
            *kind != overlay_operation_kind_v9_t::assembly_patch &&
            *kind != overlay_operation_kind_v9_t::integer_patch)
            continue;
        const overlay_static_range_v9_t patch_range{
            item.first.range.offset,
            static_cast<std::uint64_t>(item.second.bytes.size())};
        if (!overlay_range_is_provider_backed(patch_range, target_order))
            return workspace_result_t<std::shared_ptr<const byte_provider_t>>::failure(
                make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                                     "projected patch is not fully provider-backed",
                                     "overlay_journal.provider"));
        std::uint64_t target_cursor = patch_range.offset;
        const auto target_end = patch_range.offset + patch_range.size;
        for (const auto& mapping : target_order) {
            const auto mapping_end = mapping.target_start + mapping.size;
            if (mapping_end <= target_cursor)
                continue;
            if (mapping.target_start > target_cursor)
                break;
            const auto segment_end = (std::min)(target_end, mapping_end);
            patches.push_back({
                mapping.source_start + target_cursor - mapping.target_start,
                segment_end - target_cursor,
                &item.second.bytes,
                target_cursor - patch_range.offset});
            target_cursor = segment_end;
            if (target_cursor == target_end)
                break;
        }
        if (target_cursor != target_end)
            return workspace_result_t<std::shared_ptr<const byte_provider_t>>::failure(
                make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                                     "projected patch mapping is incomplete",
                                     "overlay_journal.provider"));
    }
    std::sort(patches.begin(), patches.end(),
        [](const auto& lhs, const auto& rhs) {
            return std::tie(lhs.source_offset, lhs.size, lhs.payload_offset) <
                   std::tie(rhs.source_offset, rhs.size, rhs.payload_offset);
        });
    for (std::size_t index = 1; index < patches.size(); ++index) {
        const auto previous_end = patches[index - 1].source_offset +
            patches[index - 1].size;
        if (patches[index].source_offset < previous_end)
            return workspace_result_t<std::shared_ptr<const byte_provider_t>>::failure(
                make_workspace_error(workspace_error_code_t::revision_conflict,
                                     "projected provider patches overlap",
                                     "overlay_journal.provider"));
    }

    const auto source = workspace.source_provider_handle();
    if (!source || source->size() == 0)
        return workspace_result_t<std::shared_ptr<const byte_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_unavailable,
                                 "immutable overlay source provider is unavailable",
                                 "overlay_journal.provider"));
    if (patches.empty()) {
        auto snapshot = provider_snapshot_t::capture(
            source, prepared.new_generation, cancel);
        if (!snapshot)
            return workspace_result_t<std::shared_ptr<const byte_provider_t>>::failure(
                snapshot.error());
        try {
            auto provider = std::make_shared<overlay_generation_provider_t>(
                std::static_pointer_cast<const byte_provider_t>(
                    snapshot.take_value()),
                source->member_metadata(),
                source->identity().normalized_source);
            return workspace_result_t<std::shared_ptr<const byte_provider_t>>::success(
                std::static_pointer_cast<const byte_provider_t>(
                    std::move(provider)));
        } catch (const std::bad_alloc&) {
            return workspace_result_t<std::shared_ptr<const byte_provider_t>>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                                     "overlay generation provider allocation failed",
                                     "overlay_journal.provider"));
        }
    }
    constexpr std::uint64_t workspace_overlay_spill_limit =
        1ULL * 1024ULL * 1024ULL * 1024ULL;
    if (source->size() > workspace_overlay_spill_limit)
        return workspace_result_t<std::shared_ptr<const byte_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "projected provider exceeds the workspace spill budget",
                                 "overlay_journal.provider"));
    spill_provider_options_t options;
    options.max_spill_bytes = source->size();
    options.write_chunk_bytes = 1ULL * 1024ULL * 1024ULL;
    options.mapped_window_cache.window_bytes = 4ULL * 1024ULL * 1024ULL;
    options.mapped_window_cache.max_lease_bytes = 4ULL * 1024ULL * 1024ULL;
    options.mapped_window_cache.max_cached_window_bytes =
        256ULL * 1024ULL * 1024ULL;
    options.mapped_window_cache.max_global_mapped_window_bytes =
        2ULL * 1024ULL * 1024ULL * 1024ULL;
    std::uint64_t cursor = 0;
    const auto label = workspace.identity().binary_id().to_hex() +
        "-overlay-g" + std::to_string(prepared.new_generation) +
        "-r" + std::to_string(prepared.revision);
    auto storage = spill_provider_t::from_stream(
        label,
        [source, patches = std::move(patches),
         cursor](std::uint8_t* destination, std::size_t capacity,
                 const cancellation_token_t& token) mutable
            -> workspace_result_t<std::size_t> {
            if (cursor == source->size())
                return workspace_result_t<std::size_t>::success(0);
            const auto amount = (std::min)(
                static_cast<std::uint64_t>(capacity), source->size() - cursor);
            auto read = source->read_exact(cursor, destination, amount, token);
            if (!read)
                return workspace_result_t<std::size_t>::failure(read.error());
            const auto chunk_end = cursor + amount;
            for (const auto& patch : patches) {
                const auto patch_end = patch.source_offset + patch.size;
                if (patch_end <= cursor)
                    continue;
                if (patch.source_offset >= chunk_end)
                    break;
                const auto overlap_start = (std::max)(cursor, patch.source_offset);
                const auto overlap_end = (std::min)(chunk_end, patch_end);
                std::memcpy(
                    destination + static_cast<std::size_t>(overlap_start - cursor),
                    patch.bytes->data() + static_cast<std::size_t>(
                        patch.payload_offset + overlap_start - patch.source_offset),
                    static_cast<std::size_t>(overlap_end - overlap_start));
            }
            cursor = chunk_end;
            return workspace_result_t<std::size_t>::success(
                static_cast<std::size_t>(amount));
        },
        options, cancel);
    if (!storage)
        return workspace_result_t<std::shared_ptr<const byte_provider_t>>::failure(
            storage.error());
    binding = workspace.verify_provider_binding();
    if (!binding)
        return workspace_result_t<std::shared_ptr<const byte_provider_t>>::failure(
            binding.error());
    try {
        auto provider = std::make_shared<overlay_generation_provider_t>(
            storage.take_value(), source->member_metadata(),
            overlay_provider_source(workspace, prepared));
        return workspace_result_t<std::shared_ptr<const byte_provider_t>>::success(
            std::static_pointer_cast<const byte_provider_t>(std::move(provider)));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<const byte_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "overlay generation provider allocation failed",
                                 "overlay_journal.provider"));
    }
}

projection_invalidation_hook_result_t invalidate_decompiler_cache(
    const decompiler_cache_invalidation_request_t& request,
    const std::shared_ptr<analysis_workspace_t>& workspace,
    const std::shared_ptr<workspace_database_t>& database,
    const cancellation_token_t& cancel) {
    projection_invalidation_hook_result_t result;
    if (request.invalidated_stages ==
            decompiler_cache_invalidation_flag_t::none &&
        request.affected_ranges.empty()) {
        result.succeeded = true;
        return result;
    }
    const auto publication = workspace->analysis_publication();
    if (!publication || !publication->snapshot) {
        result.detail = "workspace snapshot is unavailable for cache invalidation";
        return result;
    }
    std::vector<std::pair<address_t, std::uint64_t>> affected_functions;
    if (!request.invalidate_workspace && !request.affected_ranges.empty()) {
        for (const auto& function : publication->snapshot->functions) {
            bool affected = false;
            for (const auto& range : request.affected_ranges) {
                if (range.size == 0)
                    continue;
                for (const auto& chunk : function.chunks) {
                    const projected_range_t chunk_range{
                        chunk.rva_start,
                        chunk.rva_end > chunk.rva_start
                            ? chunk.rva_end - chunk.rva_start
                            : 0,
                        false,
                        overlay_operation_kind_v9_t::reanalysis};
                    if (range.overlaps(chunk_range)) {
                        affected = true;
                        break;
                    }
                }
                if (!affected && function.chunks.empty()) {
                    auto start = overlay_static_offset(
                        function.start, *workspace,
                        "overlay_journal.cache_invalidation");
                    auto end = overlay_static_offset(
                        function.end, *workspace,
                        "overlay_journal.cache_invalidation");
                    if (start && end && end.value() > start.value()) {
                        const projected_range_t function_range{
                            start.value(), end.value() - start.value(), false,
                            overlay_operation_kind_v9_t::reanalysis};
                        affected = range.overlaps(function_range);
                    }
                }
                if (affected)
                    break;
            }
            if (!affected)
                continue;
            auto rva = overlay_static_offset(
                function.start, *workspace,
                "overlay_journal.cache_invalidation");
            if (!rva) {
                result.detail = rva.error().message;
                return result;
            }
            affected_functions.emplace_back(function.start, rva.value());
        }
    }
    const bool invalidate_all = request.invalidate_workspace;
    if (!invalidate_all && affected_functions.empty()) {
        result.succeeded = true;
        return result;
    }
    auto service = workspace->decompiler();
    if (service) {
        const auto before = service->snapshot().memory_cache_entries;
        workspace_result_t<void> invalidated = workspace_result_t<void>::success();
        if (invalidate_all) {
            invalidated = service->invalidate({}, cancel);
        } else {
            for (const auto& function : affected_functions) {
                invalidated = service->invalidate(function.first, cancel);
                if (!invalidated)
                    break;
            }
        }
        if (!invalidated) {
            result.detail = invalidated.error().message;
            return result;
        }
        const auto after = service->snapshot().memory_cache_entries;
        result.invalidated_entry_count = before >= after ? before - after : 0;
        result.succeeded = true;
        return result;
    }
    if (invalidate_all) {
        auto ticket = database->invalidate_decompiler_cache({}, {}, cancel);
        auto waited = wait_ticket(ticket, cancel);
        if (!waited) {
            result.detail = waited.error().message;
            return result;
        }
    } else {
        for (const auto& function : affected_functions) {
            auto ticket = database->invalidate_decompiler_cache(
                function.second, {}, cancel);
            auto waited = wait_ticket(ticket, cancel);
            if (!waited) {
                result.detail = waited.error().message;
                return result;
            }
        }
    }
    result.invalidated_entry_count = affected_functions.size();
    result.succeeded = true;
    return result;
}

projection_finalize_result_t publish_projected_overlay(
    overlay_static_state_v9_t& state,
    const projection_result_t& prepared,
    const std::shared_ptr<analysis_workspace_t>& workspace,
    const std::shared_ptr<workspace_database_t>& database,
    const std::shared_ptr<const byte_provider_t>& projected_provider,
    std::function<workspace_result_t<void>(
        const std::shared_ptr<const analysis_snapshot_t>&,
        const std::shared_ptr<search_index_t>&,
        const std::shared_ptr<const managed_artifact_publication_t>&)>
        persistence_finalizer,
    const cancellation_token_t& cancel) {
    try {
        projection_invalidation_hooks_t hooks;
        hooks.decompiler_cache =
            [workspace, database, cancel](
                const decompiler_cache_invalidation_request_t& request) {
                return invalidate_decompiler_cache(
                    request, workspace, database, cancel);
            };
        hooks.packed_index =
            [workspace, projected_provider,
             target_overlay_revision = prepared.revision,
             invalidation = prepared.invalidation,
             persistence_finalizer = std::move(persistence_finalizer)](
                const packed_index_invalidation_request_t& request) {
                projection_invalidation_hook_result_t result;
                if (!projected_provider) {
                    result.detail =
                        "projected byte provider is unavailable";
                    return result;
                }
                const auto source = workspace->analysis_publication();
                if (!source || !source->snapshot ||
                    source->generation != request.source_generation) {
                    result.detail =
                        "workspace generation changed before packed-index publication";
                    return result;
                }
                std::shared_ptr<const managed_artifact_publication_t>
                    projected_managed;
                if (source->managed_artifacts) {
                    auto rebound = rebind_managed_artifact_publication(
                        *source->managed_artifacts, workspace->identity(),
                        *projected_provider, source->snapshot->image,
                        request.target_generation,
                        source->snapshot->analysis_revision,
                        target_overlay_revision,
                        workspace->cancellation_token());
                    if (!rebound) {
                        result.detail = rebound.error().message;
                        return result;
                    }
                    projected_managed = rebound.take_value();
                }
                auto persisted =
                    [persistence_finalizer, projected_managed](
                        const std::shared_ptr<const analysis_snapshot_t>& snapshot,
                        const std::shared_ptr<search_index_t>& index) {
                    return persistence_finalizer(
                        snapshot, index, projected_managed);
                };
                auto published = workspace->publish_projected_generation(
                    request.source_generation,
                    source->snapshot->analysis_revision,
                    request.target_generation,
                    target_overlay_revision,
                    projected_provider,
                    invalidation,
                    std::move(persisted));
                if (!published) {
                    result.detail = published.error().message;
                    return result;
                }
                result.invalidated_entry_count = published.value();
                result.succeeded = true;
                return result;
            };
        return overlay_projection_t::finalize_publication(
            state, prepared, hooks,
            [](const projection_publication_view_t& view,
               const projection_invalidation_hooks_t& publication_hooks) {
                projection_publication_commit_t commit;
                commit.invalidation =
                    overlay_projection_t::dispatch_invalidation(
                        view.invalidation, publication_hooks);
                commit.committed =
                    commit.invalidation.satisfies(view.invalidation);
                if (!commit.committed)
                    commit.detail = commit.invalidation.detail;
                return commit;
            });
    } catch (...) {
        projection_finalize_result_t result;
        result.code = projection_code_t::finalizer_failed;
        result.detail = "overlay publication hook allocation failed";
        return result;
    }
}

workspace_result_t<void> apply_item(
    sqlite3* database, const std::string& entity,
    const std::string& payload, std::uint64_t revision,
    const overlay_target_identity_v9_t& target) {
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
    auto operation = parse_operation(payload, target);
    if (!operation)
        return workspace_result_t<void>::failure(operation.error());
    if (entity_key(operation.value()) != entity) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "overlay materialized entity key does not match its payload",
            "overlay_journal.apply"));
    }
    auto materialized = materialized_operation(operation.take_value());
    std::string materialized_payload;
    try {
        materialized_payload = operation_json(materialized, &target).dump();
    } catch (...) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "overlay payload cannot be materialized",
            "overlay_journal.apply"));
    }
    overlay_statement_t upsert;
    auto result = upsert.prepare(database,
        "INSERT INTO overlay_items(entity_key,kind,target_discriminator,address_space,address_value,address_arch,address_mode,managed_workspace_id,managed_provider_hash,managed_provider_size,managed_artifact_hash,managed_generation,managed_entity_hash,managed_entity_key,payload_json,updated_revision) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16) ON CONFLICT(entity_key) DO UPDATE SET kind=excluded.kind,target_discriminator=excluded.target_discriminator,address_space=excluded.address_space,address_value=excluded.address_value,address_arch=excluded.address_arch,address_mode=excluded.address_mode,managed_workspace_id=excluded.managed_workspace_id,managed_provider_hash=excluded.managed_provider_hash,managed_provider_size=excluded.managed_provider_size,managed_artifact_hash=excluded.managed_artifact_hash,managed_generation=excluded.managed_generation,managed_entity_hash=excluded.managed_entity_hash,managed_entity_key=excluded.managed_entity_key,payload_json=excluded.payload_json,updated_revision=excluded.updated_revision",
        "overlay_journal.apply");
    if (!result) return result;
    result = upsert.bind_text(1, entity); if (!result) return result;
    result = upsert.bind_int(2, static_cast<std::int64_t>(materialized.kind)); if (!result) return result;
    result = bind_operation_target(upsert, 3, materialized); if (!result) return result;
    result = upsert.bind_text(15, materialized_payload); if (!result) return result;
    result = upsert.bind_uint(16, revision); if (!result) return result;
    return upsert.step_done();
}

workspace_result_t<void> migrate_operation_payloads(
    sqlite3* database, const overlay_target_identity_v9_t& target) {
    struct migration_t {
        std::uint64_t transaction_id = 0;
        std::uint64_t operation_index = 0;
        std::optional<std::string> before;
        std::string after;
    };
    std::vector<migration_t> migrations;
    overlay_statement_t query;
    auto current = query.prepare(database,
        "SELECT transaction_id,operation_index,before_json,after_json FROM overlay_operations ORDER BY transaction_id,operation_index",
        "overlay_journal.migrate_v9");
    if (!current)
        return current;
    for (;;) {
        const int status = sqlite3_step(query.get());
        if (status == SQLITE_DONE)
            break;
        if (status != SQLITE_ROW) {
            auto error = make_workspace_error(workspace_error_code_t::persistence_failure,
                "unable to read overlay operations for v9 migration",
                "overlay_journal.migrate_v9");
            error.sqlite_status = status;
            return workspace_result_t<void>::failure(std::move(error));
        }
        migration_t migration;
        migration.transaction_id = static_cast<std::uint64_t>(
            sqlite3_column_int64(query.get(), 0));
        migration.operation_index = static_cast<std::uint64_t>(
            sqlite3_column_int64(query.get(), 1));
        bool changed = false;
        try {
            if (sqlite3_column_type(query.get(), 2) != SQLITE_NULL) {
                const std::string persisted_before = overlay_column_text(query.get(), 2);
                auto parsed = parse_operation(persisted_before, target);
                if (!parsed)
                    return workspace_result_t<void>::failure(parsed.error());
                migration.before = operation_json(parsed.value(), &target).dump();
                changed = *migration.before != persisted_before;
            }
            const std::string after = overlay_column_text(query.get(), 3);
            if (after == "null") {
                migration.after = after;
            } else {
                auto parsed = parse_operation(after, target);
                if (!parsed)
                    return workspace_result_t<void>::failure(parsed.error());
                migration.after = operation_json(parsed.value(), &target).dump();
                changed = changed || migration.after != after;
            }
        } catch (...) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "overlay operation cannot be canonicalized as schema v9",
                "overlay_journal.migrate_v9"));
        }
        if (changed)
            migrations.push_back(std::move(migration));
    }
    overlay_statement_t update;
    current = update.prepare(database,
        "UPDATE overlay_operations SET before_json=?1,after_json=?2 WHERE transaction_id=?3 AND operation_index=?4",
        "overlay_journal.migrate_v9");
    if (!current)
        return current;
    for (const auto& migration : migrations) {
        current = migration.before ? update.bind_text(1, *migration.before) : update.bind_null(1);
        if (current)
            current = update.bind_text(2, migration.after);
        if (current)
            current = update.bind_uint(3, migration.transaction_id);
        if (current)
            current = update.bind_uint(4, migration.operation_index);
        if (current)
            current = update.step_done();
        if (!current)
            return current;
        current = update.reset();
        if (!current)
            return current;
    }
    return workspace_result_t<void>::success();
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

workspace_result_t<overlay_managed_entity_locator_v9_t>
bind_managed_overlay_entity_v9(
    const analysis_workspace_t& workspace,
    const generation_bound_decompiler_entity_t& binding) {
    if (workspace.target_kind() != target_kind_t::static_file ||
        binding.schema_version != managed_entity_binding_schema_version ||
        binding.reader_schema_version !=
            readers::managed::managed_reader_schema_version ||
        binding.binary_id != workspace.identity().binary_id() ||
        binding.load_profile_hash != workspace.identity().load_profile_hash() ||
        binding.provider_size != workspace.provider().size() ||
        binding.generation != workspace.generation() ||
        binding.analysis_revision != workspace.analysis_revision() ||
        binding.overlay_revision != workspace.overlay_revision() ||
        binding.type_graph_revision != workspace.analysis_revision() ||
        binding.generation == 0 || binding.artifact_hash.empty() ||
        binding.entity.kind == decompiler_entity_kind_t::native_function) {
        return workspace_result_t<overlay_managed_entity_locator_v9_t>::failure(
            make_workspace_error(
                workspace_error_code_t::provider_binding_mismatch,
                "managed overlay binding does not match the current workspace provider and generation",
                "overlay_journal.managed_binding"));
    }
    const auto publication = workspace.analysis_publication();
    if (!publication) {
        return workspace_result_t<overlay_managed_entity_locator_v9_t>::failure(
            make_workspace_error(
                workspace_error_code_t::target_not_found,
                "managed overlay binding has no current analysis publication",
                "overlay_journal.managed_binding"));
    }
    auto validated = validate_generation_bound_entity(
        workspace.identity(), *publication, binding);
    if (!validated)
        return workspace_result_t<overlay_managed_entity_locator_v9_t>::failure(
            validated.error());
    if (binding.generation != workspace.generation() ||
        binding.analysis_revision != workspace.analysis_revision() ||
        binding.overlay_revision != workspace.overlay_revision()) {
        return workspace_result_t<overlay_managed_entity_locator_v9_t>::failure(
            make_workspace_error(
                workspace_error_code_t::target_stale,
                "managed overlay binding changed during validation",
                "overlay_journal.managed_binding"));
    }
    try {
        overlay_managed_entity_locator_v9_t locator;
        locator.workspace_id = binding.binary_id.bytes;
        locator.provider_hash = workspace.identity().content_hash().bytes;
        locator.artifact_hash = binding.artifact_hash.bytes;
        locator.provider_size = binding.provider_size;
        locator.generation = binding.generation;
        locator.serialized_entity = serialize_decompiler_entity_key(binding.entity);
        locator.entity_hash = stable_serialization_hash(
            locator.serialized_entity).bytes;
        if (!locator.valid()) {
            return workspace_result_t<overlay_managed_entity_locator_v9_t>::failure(
                make_workspace_error(
                    workspace_error_code_t::invalid_argument,
                    "managed overlay entity key is invalid or does not match its artifact",
                    "overlay_journal.managed_binding"));
        }
        return workspace_result_t<overlay_managed_entity_locator_v9_t>::success(
            std::move(locator));
    } catch (...) {
        return workspace_result_t<overlay_managed_entity_locator_v9_t>::failure(
            make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "managed overlay entity serialization failed",
                "overlay_journal.managed_binding"));
    }
}

overlay_journal_t::overlay_journal_t(std::shared_ptr<analysis_workspace_t> workspace,
                                     std::shared_ptr<workspace_database_t> database,
                                     overlay_limits_t limits,
                                     overlay_target_identity_v9_t fixed_target)
    : workspace_(std::move(workspace)), database_(std::move(database)), limits_(limits),
      fixed_target_(fixed_target) {
}

overlay_journal_t::~overlay_journal_t() {
    request_cancel();
}

workspace_result_t<void> overlay_journal_t::ensure_fixed_target_binding(
    const cancellation_token_t& cancel) {
    const auto target = fixed_target_;
    auto ticket = database_->enqueue_write("analysis.overlay.target",
        [target](sqlite3* writer,
                 const cancellation_token_t& token) -> workspace_result_t<void> {
            if (token.stop_requested()) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    token.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                              : workspace_error_code_t::cancelled,
                    "overlay target binding was cancelled", "overlay_journal.target"));
            }
            auto begin = overlay_exec(writer, "BEGIN IMMEDIATE", "overlay_journal.target");
            if (!begin)
                return begin;
            [[maybe_unused]] overlay_rollback_guard_t rollback_guard(writer);
            overlay_statement_t query;
            auto current = query.prepare(writer,
                "SELECT value FROM metadata WHERE key='overlay_v9_fixed_target'",
                "overlay_journal.target");
            if (!current) {
                overlay_exec(writer, "ROLLBACK", "overlay_journal.target");
                return current;
            }
            const int status = sqlite3_step(query.get());
            if (status == SQLITE_ROW) {
                const auto persisted = deserialize_overlay_target_identity_v9(
                    overlay_column_text(query.get(), 0));
                if (!persisted || !same_target_binding(*persisted, target)) {
                    overlay_exec(writer, "ROLLBACK", "overlay_journal.target");
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::target_conflict,
                        "persisted overlay target identity does not match the workspace",
                        "overlay_journal.target"));
                }
            } else if (status != SQLITE_DONE) {
                overlay_exec(writer, "ROLLBACK", "overlay_journal.target");
                auto error = make_workspace_error(
                    workspace_error_code_t::persistence_failure,
                    "unable to read the fixed overlay target identity",
                    "overlay_journal.target");
                error.sqlite_status = status;
                return workspace_result_t<void>::failure(std::move(error));
            }
            current = persist_fixed_target(
                writer, target, "overlay_journal.target");
            if (!current) {
                overlay_exec(writer, "ROLLBACK", "overlay_journal.target");
                return current;
            }
            auto committed = overlay_exec(writer, "COMMIT", "overlay_journal.target");
            if (!committed)
                overlay_exec(writer, "ROLLBACK", "overlay_journal.target");
            return committed;
        }, cancel);
    return wait_ticket(ticket, cancel);
}

workspace_result_t<std::shared_ptr<overlay_journal_t>> overlay_journal_t::open(
    std::shared_ptr<analysis_workspace_t> workspace,
    std::shared_ptr<workspace_database_t> database,
    overlay_limits_t limits) {
    if (!workspace || !database || limits.max_operations == 0 ||
        limits.max_patch_bytes_per_item == 0 ||
        limits.max_patch_bytes_per_transaction < limits.max_patch_bytes_per_item ||
        limits.max_managed_entity_bytes == 0 ||
        limits.max_managed_entity_bytes >
            k_overlay_managed_entity_serialization_limit) {
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
    auto fixed_target = make_fixed_target_identity(*workspace);
    if (!fixed_target)
        return workspace_result_t<std::shared_ptr<overlay_journal_t>>::failure(
            fixed_target.error());
    auto journal = std::shared_ptr<overlay_journal_t>(
        new overlay_journal_t(std::move(workspace), std::move(database), limits,
                              fixed_target.take_value()));
    auto target_bound = journal->ensure_fixed_target_binding(journal->cancellation_.token());
    if (!target_bound)
        return workspace_result_t<std::shared_ptr<overlay_journal_t>>::failure(
            target_bound.error());
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
    std::shared_ptr<const byte_provider_t> recovered_provider;
    const bool requires_projection_restore =
        journal->revision_ > current_revision ||
        !journal->patch_operations().empty();
    if (requires_projection_restore) {
        const auto target = journal->fixed_target();
        auto state = make_v9_preflight_state(
            journal->snapshot(), *owner, target);
        if (!state)
            return attach_failure(state.error());
        auto projected = overlay_projection_t::prepare(
            state.value(), target.generation);
        if (!projected)
            return attach_failure(
                projection_error(projected, "overlay_journal.open"));
        if (projected.revision != journal->revision_ ||
            projected.new_generation != target.generation)
            return attach_failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "recovered overlay projection has inconsistent revisions",
                "overlay_journal.open"));
        auto provider = materialize_projected_provider(
            *owner, projected, journal->cancellation_.token());
        if (!provider)
            return attach_failure(provider.error());
        recovered_provider = provider.take_value();
    }
    auto registered = owner->register_lifecycle_participant(journal);
    if (!registered)
        return attach_failure(registered.error());
    if (journal->revision_ > current_revision) {
        const auto restored = owner->restore_overlay_revision(current_revision,
                                                              journal->revision_,
                                                              journal->fixed_target_.generation,
                                                              recovered_provider);
        if (!restored)
            return attach_failure(restored.error());
    } else if (recovered_provider) {
        auto restored = owner->restore_projected_provider(
            owner->generation(), owner->analysis_revision(),
            owner->overlay_revision(), recovered_provider);
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
        [target = fixed_target_](sqlite3* writer, const cancellation_token_t& token) {
            if (token.stop_requested()) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::cancelled,
                    "overlay recovery cancelled", "overlay_journal.recovery"));
            }
            auto begin = overlay_exec(writer, "BEGIN IMMEDIATE", "overlay_journal.recovery");
            if (!begin) return begin;
            [[maybe_unused]] overlay_rollback_guard_t rollback_guard(writer);
            auto migrated = migrate_operation_payloads(writer, target);
            if (!migrated) {
                overlay_exec(writer, "ROLLBACK", "overlay_journal.recovery");
                return migrated;
            }
            auto cleared = overlay_exec(writer, "DELETE FROM overlay_items",
                                        "overlay_journal.recovery");
            if (!cleared) { overlay_exec(writer, "ROLLBACK", "overlay_journal.recovery"); return cleared; }
            overlay_statement_t statement;
            auto result = statement.prepare(writer,
                "SELECT o.entity_key,o.before_json,o.after_json,t.revision,o.target_discriminator,o.address_space,o.address_value,o.address_arch,o.address_mode,o.managed_workspace_id,o.managed_provider_hash,o.managed_provider_size,o.managed_artifact_hash,o.managed_generation,o.managed_entity_hash,o.managed_entity_key FROM overlay_operations o JOIN overlay_transactions t ON t.transaction_id=o.transaction_id WHERE t.applied=1 AND t.abandoned=0 ORDER BY t.transaction_id,o.operation_index",
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
                const std::string before =
                    sqlite3_column_type(statement.get(), 1) == SQLITE_NULL
                        ? std::string("null")
                        : overlay_column_text(statement.get(), 1);
                const std::string after = overlay_column_text(statement.get(), 2);
                const bool removal = after == "null";
                const std::string& source = removal ? before : after;
                if (source == "null") {
                    overlay_exec(writer, "ROLLBACK", "overlay_journal.recovery");
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "overlay journal operation has no replay identity",
                        "overlay_journal.recovery"));
                }
                auto parsed = parse_operation(source, target);
                if (!parsed ||
                    entity_key(parsed.value()) !=
                        overlay_column_text(statement.get(), 0) ||
                    !operation_target_matches_columns(
                        statement.get(), 4, parsed.value(),
                        target.generation, removal)) {
                    overlay_exec(writer, "ROLLBACK", "overlay_journal.recovery");
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "overlay journal storage identity is inconsistent",
                        "overlay_journal.recovery"));
                }
                result = apply_item(
                    writer, overlay_column_text(statement.get(), 0), after,
                    static_cast<std::uint64_t>(
                        sqlite3_column_int64(statement.get(), 3)),
                    target);
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
            "SELECT entity_key,payload_json,target_discriminator,address_space,address_value,address_arch,address_mode,managed_workspace_id,managed_provider_hash,managed_provider_size,managed_artifact_hash,managed_generation,managed_entity_hash,managed_entity_key FROM overlay_items ORDER BY entity_key",
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
            auto operation = parse_operation(overlay_column_text(statement.get(), 1),
                                             fixed_target_);
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
                                                patch_bytes, true);
            if (!validated)
                return validated;
            if (key != entity_key(operation.value()) ||
                !operation_target_matches_columns(
                    statement.get(), 2, operation.value(),
                    fixed_target_.generation) ||
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
        next_transaction_id_ = state.next_transaction;
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

    std::unique_lock<std::mutex> publication_lock(publication_mutex_);
    std::unique_lock<std::shared_mutex> mutation_lock(workspace->mutation_mutex());
    const auto local_snapshot = snapshot();
    const auto target = fixed_target();
    if (target.kind != overlay_target_kind_v9_t::static_image) {
        return workspace_result_t<overlay_transaction_result_t>::failure(
            make_workspace_error(
                workspace_error_code_t::target_conflict,
                "overlay projection requires a static workspace target",
                "overlay_journal.transact"));
    }
    if (workspace->generation() != target.generation) {
        return workspace_result_t<overlay_transaction_result_t>::failure(make_workspace_error(
            workspace_error_code_t::stale_generation,
            "workspace generation no longer matches the fixed overlay target",
            "overlay_journal.transact"));
    }
    if (workspace->overlay_revision() != local_snapshot.revision) {
        return workspace_result_t<overlay_transaction_result_t>::failure(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "workspace and overlay journal revisions differ",
            "overlay_journal.transact"));
    }
    std::size_t total_patch_bytes = 0;
    std::vector<std::string> keys;
    keys.reserve(request.operations.size());
    std::vector<overlay_operation_v9_t> v9_operations;
    v9_operations.reserve(request.operations.size());
    std::unordered_map<std::string, std::pair<std::uint64_t, std::uint64_t>> patch_ranges;
    for (const auto& operation : request.operations) {
        auto validated = validate_operation(
            operation, limits_, *workspace, total_patch_bytes,
            request.idempotency_key.has_value());
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
        auto adapted = operation_to_v9(operation, *workspace, target,
                                       "overlay_journal.transact");
        if (!adapted)
            return workspace_result_t<overlay_transaction_result_t>::failure(
                adapted.error());
        v9_operations.push_back(adapted.take_value());
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
    std::optional<std::string> legacy_request_hash;
    if (!request.dry_run) {
        const auto hash_target = target_at_generation(target, 1);
        json request_json;
        request_json["expected_revision"] = request.expected_revision
            ? json(std::to_string(*request.expected_revision)) : json(nullptr);
        request_json["idempotency_key"] = request.idempotency_key
            ? json(*request.idempotency_key) : json(nullptr);
        request_json["operations"] = json::array();
        for (const auto& operation : request.operations) {
            auto canonical = operation;
            if (canonical.target_discriminator ==
                    overlay_target_discriminator_v9_t::managed_entity &&
                canonical.managed_locator)
                canonical.managed_locator->generation = hash_target.generation;
            request_json["operations"].push_back(
                operation_json(canonical, &hash_target));
        }
        auto request_hash_result = sha256_text(request_json.dump(), cancel);
        if (!request_hash_result)
            return workspace_result_t<overlay_transaction_result_t>::failure(
                request_hash_result.error());
        request_hash = request_hash_result.value().to_hex();
        const bool legacy_compatible = request.idempotency_key &&
            std::all_of(request.operations.begin(), request.operations.end(),
                [](const overlay_operation_t& operation) {
                    return operation.target_discriminator ==
                               overlay_target_discriminator_v9_t::native_address &&
                        !operation.managed_locator &&
                        static_cast<unsigned>(operation.kind) <=
                               static_cast<unsigned>(overlay_operation_kind_t::integer_patch) &&
                        operation.reanalysis_flags == 0 && !operation.remove;
                });
        if (legacy_compatible) {
            json legacy_request;
            legacy_request["expected_revision"] = request.expected_revision
                ? json(std::to_string(*request.expected_revision)) : json(nullptr);
            legacy_request["idempotency_key"] = *request.idempotency_key;
            legacy_request["operations"] = json::array();
            for (const auto& operation : request.operations)
                legacy_request["operations"].push_back(legacy_operation_json(operation));
            auto legacy_hash = sha256_text(legacy_request.dump(), cancel);
            if (!legacy_hash)
                return workspace_result_t<overlay_transaction_result_t>::failure(
                    legacy_hash.error());
            legacy_request_hash = legacy_hash.value().to_hex();
        }
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
                const std::string persisted_hash = overlay_column_text(statement.get(), 0);
                if (persisted_hash != request_hash &&
                    (!legacy_request_hash || persisted_hash != *legacy_request_hash)) {
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
        std::size_t current_patch_bytes = 0;
        for (const auto& operation : request.operations) {
            auto validated = validate_operation(
                operation, limits_, *workspace, current_patch_bytes);
            if (!validated)
                return workspace_result_t<overlay_transaction_result_t>::failure(
                    validated.error());
        }
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

    const std::uint64_t local_revision = local_snapshot.revision;
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
    auto preflight_state = make_v9_preflight_state(
        local_snapshot, *workspace, target);
    if (!preflight_state)
        return workspace_result_t<overlay_transaction_result_t>::failure(
            preflight_state.error());
    overlay_transaction_v9_t transaction;
    transaction.target = target;
    transaction.expected_revision = local_revision;
    transaction.operations = v9_operations;
    auto prepared = overlay_projection_t::prepare_transaction(
        preflight_state.value(), transaction,
        target.generation, projection_limits(limits_));
    if (!prepared)
        return workspace_result_t<overlay_transaction_result_t>::failure(
            projection_error(prepared, "overlay_journal.transact"));
    const auto reanalysis = incremental_reanalysis_t::compute_scope(
        prepared.changes, preflight_state.value(), target.generation);
    if (!reanalysis ||
        reanalysis.scope.ranges != prepared.invalidation.affected_ranges ||
        reanalysis.invalidation.affected_entities !=
            prepared.invalidation.affected_entities ||
        reanalysis.scope.stage_flags != prepared.invalidation.invalidated_stages ||
        reanalysis.scope.total_patched_bytes !=
            prepared.invalidation.total_patched_bytes) {
        return workspace_result_t<overlay_transaction_result_t>::failure(
            make_workspace_error(
                workspace_error_code_t::integrity_failure,
                reanalysis.detail.empty()
                    ? "incremental reanalysis disagrees with overlay projection"
                    : reanalysis.detail,
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

    auto projected_provider = materialize_projected_provider(
        *workspace, prepared, cancel);
    if (!projected_provider)
        return workspace_result_t<overlay_transaction_result_t>::failure(
            projected_provider.error());
    std::shared_ptr<std::unordered_map<std::string, overlay_operation_t>> next_items;
    try {
        next_items = std::make_shared<
            std::unordered_map<std::string, overlay_operation_t>>();
        next_items->reserve(local_snapshot.items.size());
        for (const auto& item : local_snapshot.items)
            next_items->emplace(item.first, item.second);
        for (std::size_t index = 0; index < request.operations.size(); ++index) {
            if (removes_value(request.operations[index]))
                next_items->erase(keys[index]);
            else
                next_items->insert_or_assign(
                    keys[index], materialized_operation(request.operations[index]));
        }
    } catch (...) {
        return workspace_result_t<overlay_transaction_result_t>::failure(
            make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "overlay publication state allocation failed",
                "overlay_journal.transact"));
    }

    auto result_holder = std::make_shared<overlay_transaction_result_t>();
    auto committed_state = std::make_shared<overlay_db_state_t>();
    const auto operations = request.operations;
    const auto idempotency = request.idempotency_key;
    const auto next_target = target_at_generation(target, prepared.new_generation);
    auto persistence_finalizer =
        [this, database = database_, operations, keys, idempotency,
         request_hash, legacy_request_hash,
         request_expected = request.expected_revision, target, next_target,
         local_revision, next_items, result_holder, committed_state,
         cancel](const std::shared_ptr<const analysis_snapshot_t>& snapshot,
                 const std::shared_ptr<search_index_t>& index,
                 const std::shared_ptr<const managed_artifact_publication_t>&
                     managed_publication)
            -> workspace_result_t<void> {
        {
            std::shared_lock<std::shared_mutex> state_lock(state_mutex_);
            if (revision_ != local_revision || fixed_target_ != target) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::revision_conflict,
                    "overlay journal changed before atomic publication",
                "overlay_journal.commit"));
            }
        }
        auto staged = stage_projected_candidate(
            database, snapshot, index, managed_publication, cancel);
        if (!staged)
            return workspace_result_t<void>::failure(staged.error());
        const auto candidate = staged.take_value();
        auto ticket = database->enqueue_write("analysis.overlay.commit",
        [operations, keys, idempotency, request_hash, legacy_request_hash,
         request_expected, target = next_target, local_revision,
         result_holder, committed_state, candidate, snapshot](sqlite3* writer,
                        const cancellation_token_t& token) -> workspace_result_t<void> {
            if (token.stop_requested())
                return workspace_result_t<void>::failure(make_workspace_error(
                    token.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                              : workspace_error_code_t::cancelled,
                    "overlay commit cancelled", "overlay_journal.commit"));
            auto begin = overlay_exec(writer, "BEGIN IMMEDIATE", "overlay_journal.commit");
            if (!begin) return begin;
            [[maybe_unused]] overlay_rollback_guard_t rollback_guard(writer);
            auto state_result = read_overlay_state(writer, "overlay_journal.commit");
            if (!state_result) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return workspace_result_t<void>::failure(state_result.error()); }
            auto state = state_result.take_value();
            if (state.revision != local_revision) {
                overlay_exec(writer, "ROLLBACK", "overlay_journal.commit");
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::revision_conflict,
                    "overlay database changed before atomic publication",
                    "overlay_journal.commit"));
            }
            if (idempotency) {
                overlay_statement_t idempotency_query;
                auto current = idempotency_query.prepare(writer,
                    "SELECT request_hash,result_json FROM overlay_idempotency WHERE idempotency_key=?1",
                    "overlay_journal.commit");
                if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                current = idempotency_query.bind_text(1, *idempotency); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                const int status = sqlite3_step(idempotency_query.get());
                if (status == SQLITE_ROW) {
                    const std::string persisted_hash = overlay_column_text(idempotency_query.get(), 0);
                    if (persisted_hash != request_hash &&
                        (!legacy_request_hash || persisted_hash != *legacy_request_hash)) {
                        overlay_exec(writer, "ROLLBACK", "overlay_journal.commit");
                        return workspace_result_t<void>::failure(make_workspace_error(
                            workspace_error_code_t::revision_conflict,
                            "idempotency key was already used for a different transaction",
                            "overlay_journal.commit"));
                    }
                    overlay_exec(writer, "ROLLBACK", "overlay_journal.commit");
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::revision_conflict,
                        "idempotency state changed before atomic publication",
                        "overlay_journal.commit"));
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
                "INSERT INTO overlay_operations(transaction_id,operation_index,kind,entity_key,target_discriminator,address_space,address_value,address_arch,address_mode,managed_workspace_id,managed_provider_hash,managed_provider_size,managed_artifact_hash,managed_generation,managed_entity_hash,managed_entity_key,before_json,after_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
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
                    ? std::string("null") : operation_json(operations[index], &target).dump();
                current = operation_statement.bind_uint(1, transaction_id); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                current = operation_statement.bind_uint(2, index); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                current = operation_statement.bind_int(3, static_cast<std::int64_t>(operations[index].kind)); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                current = operation_statement.bind_text(4, keys[index]); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                current = bind_operation_target(operation_statement, 5, operations[index]); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                if (before) current = operation_statement.bind_text(17, *before); else current = operation_statement.bind_null(17); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                current = operation_statement.bind_text(18, after); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                current = operation_statement.step_done(); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                current = operation_statement.reset(); if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
                current = apply_item(writer, keys[index], after, new_revision,
                                     target);
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

            current = persist_fixed_target(
                writer, target, "overlay_journal.commit");
            if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }

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
            current = promote_projected_candidate(
                writer, *candidate, *snapshot, token,
                "overlay_journal.commit");
            if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return current; }
            state.revision = new_revision;
            state.cursor = transaction_id;
            state.next_transaction = transaction_id + 1;
            *committed_state = state;
            *result_holder = std::move(transaction_result);
            auto committed = overlay_exec(writer, "COMMIT", "overlay_journal.commit");
            if (!committed) { overlay_exec(writer, "ROLLBACK", "overlay_journal.commit"); return committed; }
            return workspace_result_t<void>::success();
        }, cancel);
        auto waited = wait_ticket(ticket, cancel);
        if (!waited) {
            static_cast<void>(candidate->discard());
            return waited;
        }
        auto acknowledged = candidate->finalize();
        if (!acknowledged)
            return acknowledged;
        publication_epoch_.fetch_add(1, std::memory_order_acq_rel);
        {
            std::unique_lock<std::shared_mutex> state_lock(state_mutex_);
            items_.swap(*next_items);
            revision_ = committed_state->revision;
            history_cursor_ = committed_state->cursor;
            next_transaction_id_ = committed_state->next_transaction;
            history_epoch_ = committed_state->epoch;
            fixed_target_ = next_target;
        }
        return workspace_result_t<void>::success();
    };
    mutation_lock.unlock();
    const auto finalized = publish_projected_overlay(
        preflight_state.value(), prepared, workspace, database_,
        projected_provider.value(), std::move(persistence_finalizer), cancel);
    if ((publication_epoch_.load(std::memory_order_acquire) & 1U) != 0)
        publication_epoch_.fetch_add(1, std::memory_order_release);
    if (!finalized)
        return workspace_result_t<overlay_transaction_result_t>::failure(
            projection_finalize_error(finalized, "overlay_journal.transact"));
    return workspace_result_t<overlay_transaction_result_t>::success(*result_holder);
}

workspace_result_t<overlay_transaction_result_t> overlay_journal_t::transact_v9(
    const overlay_transaction_v9_t& transaction,
    bool dry_run,
    std::optional<std::string> idempotency_key,
    const cancellation_token_t& cancel) {
    auto workspace = workspace_.lock();
    if (!workspace || workspace->closing()) {
        return workspace_result_t<overlay_transaction_result_t>::failure(make_workspace_error(
            workspace_error_code_t::workspace_closing,
            "overlay workspace is closing", "overlay_journal.adapter"));
    }
    const auto target = fixed_target();
    if (target.kind != overlay_target_kind_v9_t::static_image) {
        return workspace_result_t<overlay_transaction_result_t>::failure(make_workspace_error(
            workspace_error_code_t::target_conflict,
            "overlay v9 transactions require a static workspace",
            "overlay_journal.adapter"));
    }
    if (!transaction.target.valid() || transaction.target != target) {
        return workspace_result_t<overlay_transaction_result_t>::failure(make_workspace_error(
            workspace_error_code_t::stale_generation,
            "overlay v9 transaction target does not match the fixed workspace target",
            "overlay_journal.adapter"));
    }
    overlay_transaction_request_t request;
    request.dry_run = dry_run;
    request.expected_revision = transaction.expected_revision;
    request.idempotency_key = std::move(idempotency_key);
    request.operations.reserve(transaction.operations.size());
    for (const auto& operation : transaction.operations) {
        try {
            (void)serialize_overlay_operation_record_v9({target, operation});
        } catch (...) {
            return workspace_result_t<overlay_transaction_result_t>::failure(make_workspace_error(
                workspace_error_code_t::invalid_argument,
                "overlay v9 transaction contains an invalid operation",
                "overlay_journal.adapter"));
        }
        auto adapted = operation_from_v9(operation, *workspace, target);
        if (!adapted)
            return workspace_result_t<overlay_transaction_result_t>::failure(adapted.error());
        request.operations.push_back(adapted.take_value());
    }
    return transact(request, cancel);
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
    std::unique_lock<std::mutex> publication_lock(publication_mutex_);
    std::unique_lock<std::shared_mutex> mutation_lock(workspace->mutation_mutex());
    const auto local_snapshot = snapshot();
    const auto target = fixed_target();
    if (target.kind != overlay_target_kind_v9_t::static_image) {
        return workspace_result_t<overlay_transaction_result_t>::failure(
            make_workspace_error(
                workspace_error_code_t::target_conflict,
                "overlay history projection requires a static workspace target",
                "overlay_journal.history"));
    }
    if (workspace->generation() != target.generation ||
        workspace->overlay_revision() != local_snapshot.revision) {
        return workspace_result_t<overlay_transaction_result_t>::failure(
            make_workspace_error(
                workspace_error_code_t::revision_conflict,
                "workspace generation or overlay revision changed",
                "overlay_journal.history"));
    }
    struct history_projection_operation_t final {
        std::string key;
        overlay_operation_t operation;
    };
    std::uint64_t selected_transaction_id = 0;
    std::vector<history_projection_operation_t> projection_operations;
    {
        auto auth_check = database_->with_reader(
            [&](sqlite3* reader) -> workspace_result_t<void> {
                auto state_result = read_overlay_state(reader, "overlay_journal.history");
                if (!state_result) return workspace_result_t<void>::failure(state_result.error());
                if (state_result.value().revision != local_snapshot.revision)
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::revision_conflict,
                        "authoritative revision mismatch", "overlay_journal.history"));
                overlay_statement_t target_statement;
                auto current = target_statement.prepare(reader,
                    redo
                        ? "SELECT transaction_id FROM overlay_transactions WHERE applied=0 AND abandoned=0 AND transaction_id>?1 ORDER BY transaction_id LIMIT 1"
                        : "SELECT transaction_id FROM overlay_transactions WHERE applied=1 AND abandoned=0 AND transaction_id<=?1 ORDER BY transaction_id DESC LIMIT 1",
                    "overlay_journal.history");
                if (!current)
                    return current;
                current = target_statement.bind_uint(1, state_result.value().cursor);
                if (!current)
                    return current;
                int status = sqlite3_step(target_statement.get());
                if (status == SQLITE_DONE)
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::target_not_found,
                        redo ? "no overlay transaction is available to redo"
                             : "no overlay transaction is available to undo",
                        "overlay_journal.history"));
                if (status != SQLITE_ROW ||
                    sqlite3_column_int64(target_statement.get(), 0) <= 0) {
                    auto error = make_workspace_error(
                        workspace_error_code_t::persistence_failure,
                        "unable to select overlay history transaction",
                        "overlay_journal.history");
                    error.sqlite_status = status;
                    return workspace_result_t<void>::failure(std::move(error));
                }
                selected_transaction_id = static_cast<std::uint64_t>(
                    sqlite3_column_int64(target_statement.get(), 0));
                overlay_statement_t operations;
                current = operations.prepare(reader,
                    redo
                        ? "SELECT entity_key,before_json,after_json,operation_index,target_discriminator,address_space,address_value,address_arch,address_mode,managed_workspace_id,managed_provider_hash,managed_provider_size,managed_artifact_hash,managed_generation,managed_entity_hash,managed_entity_key FROM overlay_operations WHERE transaction_id=?1 ORDER BY operation_index"
                        : "SELECT entity_key,before_json,after_json,operation_index,target_discriminator,address_space,address_value,address_arch,address_mode,managed_workspace_id,managed_provider_hash,managed_provider_size,managed_artifact_hash,managed_generation,managed_entity_hash,managed_entity_key FROM overlay_operations WHERE transaction_id=?1 ORDER BY operation_index DESC",
                    "overlay_journal.history");
                if (!current)
                    return current;
                current = operations.bind_uint(1, selected_transaction_id);
                if (!current)
                    return current;
                for (;;) {
                    status = sqlite3_step(operations.get());
                    if (status == SQLITE_DONE)
                        break;
                    if (status != SQLITE_ROW) {
                        auto error = make_workspace_error(
                            workspace_error_code_t::persistence_failure,
                            "unable to read overlay history projection",
                            "overlay_journal.history");
                        error.sqlite_status = status;
                        return workspace_result_t<void>::failure(std::move(error));
                    }
                    const std::string desired = sqlite3_column_type(
                        operations.get(), redo ? 2 : 1) == SQLITE_NULL
                        ? std::string("null")
                        : overlay_column_text(operations.get(), redo ? 2 : 1);
                    const std::string inverse = sqlite3_column_type(
                        operations.get(), redo ? 1 : 2) == SQLITE_NULL
                        ? std::string("null")
                        : overlay_column_text(operations.get(), redo ? 1 : 2);
                    const std::string& source = desired == "null" ? inverse : desired;
                    if (source == "null")
                        return workspace_result_t<void>::failure(make_workspace_error(
                            workspace_error_code_t::integrity_failure,
                            "overlay history operation has no reversible payload",
                            "overlay_journal.history"));
                    auto parsed = parse_operation(source, target);
                    if (!parsed)
                        return workspace_result_t<void>::failure(parsed.error());
                    parsed.value().remove = desired == "null";
                    const std::string key = overlay_column_text(operations.get(), 0);
                    if (entity_key(parsed.value()) != key ||
                        !operation_target_matches_columns(
                            operations.get(), 4, parsed.value(),
                            target.generation, true) ||
                        sqlite3_column_int64(operations.get(), 3) < 0)
                        return workspace_result_t<void>::failure(make_workspace_error(
                            workspace_error_code_t::integrity_failure,
                            "overlay history operation identity is invalid",
                            "overlay_journal.history"));
                    projection_operations.push_back({
                        key, parsed.take_value()});
                }
                if (projection_operations.empty())
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "overlay history transaction has no operations",
                        "overlay_journal.history"));
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
    std::size_t total_patch_bytes = 0;
    std::vector<overlay_operation_v9_t> v9_operations;
    v9_operations.reserve(projection_operations.size());
    for (auto& item : projection_operations) {
        auto projection_operation = item.operation;
        if (projection_operation.target_discriminator ==
                overlay_target_discriminator_v9_t::managed_entity &&
            projection_operation.managed_locator) {
            std::size_t historical_patch_bytes = 0;
            auto historical = validate_operation(
                projection_operation, limits_, *workspace,
                historical_patch_bytes,
                true);
            if (!historical)
                return workspace_result_t<overlay_transaction_result_t>::failure(
                    historical.error());
            projection_operation.managed_locator->generation =
                target.generation;
        }
        auto validated = validate_operation(
            projection_operation, limits_, *workspace, total_patch_bytes);
        if (!validated)
            return workspace_result_t<overlay_transaction_result_t>::failure(
                validated.error());
        auto adapted = operation_to_v9(
            projection_operation, *workspace, target,
            "overlay_journal.history");
        if (!adapted)
            return workspace_result_t<overlay_transaction_result_t>::failure(
                adapted.error());
        v9_operations.push_back(adapted.take_value());
    }
    auto preflight_state = make_v9_preflight_state(
        local_snapshot, *workspace, target);
    if (!preflight_state)
        return workspace_result_t<overlay_transaction_result_t>::failure(
            preflight_state.error());
    overlay_transaction_v9_t transaction;
    transaction.target = target;
    transaction.expected_revision = local_snapshot.revision;
    transaction.operations = std::move(v9_operations);
    auto prepared = overlay_projection_t::prepare_transaction(
        preflight_state.value(), transaction,
        target.generation, projection_limits(limits_));
    if (!prepared)
        return workspace_result_t<overlay_transaction_result_t>::failure(
            projection_error(prepared, "overlay_journal.history"));
    const auto reanalysis = incremental_reanalysis_t::compute_scope(
        prepared.changes, preflight_state.value(), target.generation);
    if (!reanalysis ||
        reanalysis.scope.ranges != prepared.invalidation.affected_ranges ||
        reanalysis.invalidation.affected_entities !=
            prepared.invalidation.affected_entities ||
        reanalysis.scope.stage_flags != prepared.invalidation.invalidated_stages ||
        reanalysis.scope.total_patched_bytes !=
            prepared.invalidation.total_patched_bytes) {
        return workspace_result_t<overlay_transaction_result_t>::failure(
            make_workspace_error(
                workspace_error_code_t::integrity_failure,
                reanalysis.detail.empty()
                    ? "incremental reanalysis disagrees with overlay history projection"
                    : reanalysis.detail,
                "overlay_journal.history"));
    }
    auto projected_provider = materialize_projected_provider(
        *workspace, prepared, cancel);
    if (!projected_provider)
        return workspace_result_t<overlay_transaction_result_t>::failure(
            projected_provider.error());
    std::shared_ptr<std::unordered_map<std::string, overlay_operation_t>> next_items;
    try {
        next_items = std::make_shared<
            std::unordered_map<std::string, overlay_operation_t>>();
        next_items->reserve(local_snapshot.items.size());
        for (const auto& item : local_snapshot.items)
            next_items->emplace(item.first, item.second);
        for (const auto& item : projection_operations) {
            if (removes_value(item.operation))
                next_items->erase(item.key);
            else
                next_items->insert_or_assign(
                    item.key, materialized_operation(item.operation));
        }
    } catch (...) {
        return workspace_result_t<overlay_transaction_result_t>::failure(
            make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "overlay history publication state allocation failed",
                "overlay_journal.history"));
    }
    auto result_holder = std::make_shared<overlay_transaction_result_t>();
    auto committed_state = std::make_shared<overlay_db_state_t>();
    const auto next_target = target_at_generation(target, prepared.new_generation);
    auto persistence_finalizer =
        [this, database = database_, redo, expected_revision,
         selected_transaction_id, target, next_target,
         local_revision = local_snapshot.revision, next_items,
         result_holder, committed_state,
         cancel](const std::shared_ptr<const analysis_snapshot_t>& snapshot,
                 const std::shared_ptr<search_index_t>& index,
                 const std::shared_ptr<const managed_artifact_publication_t>&
                     managed_publication)
            -> workspace_result_t<void> {
        {
            std::shared_lock<std::shared_mutex> state_lock(state_mutex_);
            if (revision_ != local_revision || fixed_target_ != target) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::revision_conflict,
                    "overlay journal changed before atomic history publication",
                "overlay_journal.history"));
            }
        }
        auto staged = stage_projected_candidate(
            database, snapshot, index, managed_publication, cancel);
        if (!staged)
            return workspace_result_t<void>::failure(staged.error());
        const auto candidate = staged.take_value();
        auto ticket = database->enqueue_write(
        redo ? "analysis.overlay.redo" : "analysis.overlay.undo",
        [redo, expected_revision, selected_transaction_id, local_revision,
         target = next_target, result_holder, committed_state,
         candidate, snapshot](sqlite3* writer,
                                                 const cancellation_token_t& token) {
            if (token.stop_requested())
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::cancelled,
                    "overlay history action cancelled", "overlay_journal.history"));
            auto begin = overlay_exec(writer, "BEGIN IMMEDIATE", "overlay_journal.history");
            if (!begin) return begin;
            [[maybe_unused]] overlay_rollback_guard_t rollback_guard(writer);
            auto state_result = read_overlay_state(writer, "overlay_journal.history");
            if (!state_result) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return workspace_result_t<void>::failure(state_result.error()); }
            auto state = state_result.take_value();
            if (state.revision != local_revision) {
                overlay_exec(writer, "ROLLBACK", "overlay_journal.history");
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::revision_conflict,
                    "overlay database changed before atomic history publication",
                    "overlay_journal.history"));
            }
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
            if (status != SQLITE_ROW ||
                sqlite3_column_int64(target_statement.get(), 0) <= 0) {
                overlay_exec(writer, "ROLLBACK", "overlay_journal.history");
                auto error = make_workspace_error(workspace_error_code_t::persistence_failure,
                    "unable to select overlay history transaction", "overlay_journal.history");
                error.sqlite_status = status;
                return workspace_result_t<void>::failure(std::move(error));
            }
            const std::uint64_t transaction_id = static_cast<std::uint64_t>(sqlite3_column_int64(target_statement.get(), 0));
            if (transaction_id != selected_transaction_id) {
                overlay_exec(writer, "ROLLBACK", "overlay_journal.history");
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::revision_conflict,
                    "overlay history cursor changed before atomic publication",
                    "overlay_journal.history"));
            }
            const std::uint64_t new_revision = state.revision + 1;
            overlay_statement_t operation_statement;
            current = operation_statement.prepare(writer,
                redo
                    ? "SELECT entity_key,before_json,after_json,operation_index,target_discriminator,address_space,address_value,address_arch,address_mode,managed_workspace_id,managed_provider_hash,managed_provider_size,managed_artifact_hash,managed_generation,managed_entity_hash,managed_entity_key FROM overlay_operations WHERE transaction_id=?1 ORDER BY operation_index"
                    : "SELECT entity_key,before_json,after_json,operation_index,target_discriminator,address_space,address_value,address_arch,address_mode,managed_workspace_id,managed_provider_hash,managed_provider_size,managed_artifact_hash,managed_generation,managed_entity_hash,managed_entity_key FROM overlay_operations WHERE transaction_id=?1 ORDER BY operation_index DESC",
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
                const std::string payload = sqlite3_column_type(
                    operation_statement.get(), redo ? 2 : 1) == SQLITE_NULL
                    ? std::string("null")
                    : overlay_column_text(operation_statement.get(),
                                          redo ? 2 : 1);
                const std::string inverse = sqlite3_column_type(
                    operation_statement.get(), redo ? 1 : 2) == SQLITE_NULL
                    ? std::string("null")
                    : overlay_column_text(operation_statement.get(),
                                          redo ? 1 : 2);
                const std::string& source = payload == "null" ? inverse : payload;
                auto parsed = source == "null"
                    ? workspace_result_t<overlay_operation_t>::failure(
                          make_workspace_error(
                              workspace_error_code_t::integrity_failure,
                              "overlay history operation has no storage identity",
                              "overlay_journal.history"))
                    : parse_operation(source, target);
                if (!parsed || entity_key(parsed.value()) != key ||
                    !operation_target_matches_columns(
                        operation_statement.get(), 4, parsed.value(),
                        target.generation, true)) {
                    overlay_exec(writer, "ROLLBACK", "overlay_journal.history");
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "overlay history storage identity is inconsistent",
                        "overlay_journal.history"));
                }
                current = apply_item(writer, key, payload, new_revision, target);
                if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }
                action_result.operations.push_back({
                    static_cast<std::size_t>(sqlite3_column_int64(operation_statement.get(), 3)),
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

            current = persist_fixed_target(
                writer, target, "overlay_journal.history");
            if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }

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
            current = promote_projected_candidate(
                writer, *candidate, *snapshot, token,
                "overlay_journal.history");
            if (!current) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return current; }
            state.revision = new_revision;
            state.cursor = cursor;
            *committed_state = state;
            *result_holder = std::move(action_result);
            auto committed = overlay_exec(writer, "COMMIT", "overlay_journal.history");
            if (!committed) { overlay_exec(writer, "ROLLBACK", "overlay_journal.history"); return committed; }
            return workspace_result_t<void>::success();
        }, cancel);
        auto waited = wait_ticket(ticket, cancel);
        if (!waited) {
            static_cast<void>(candidate->discard());
            return waited;
        }
        auto acknowledged = candidate->finalize();
        if (!acknowledged)
            return acknowledged;
        publication_epoch_.fetch_add(1, std::memory_order_acq_rel);
        {
            std::unique_lock<std::shared_mutex> state_lock(state_mutex_);
            items_.swap(*next_items);
            revision_ = committed_state->revision;
            history_cursor_ = committed_state->cursor;
            next_transaction_id_ = committed_state->next_transaction;
            history_epoch_ = committed_state->epoch;
            fixed_target_ = next_target;
        }
        return workspace_result_t<void>::success();
    };
    mutation_lock.unlock();
    const auto finalized = publish_projected_overlay(
        preflight_state.value(), prepared, workspace, database_,
        projected_provider.value(), std::move(persistence_finalizer), cancel);
    if ((publication_epoch_.load(std::memory_order_acquire) & 1U) != 0)
        publication_epoch_.fetch_add(1, std::memory_order_release);
    if (!finalized)
        return workspace_result_t<overlay_transaction_result_t>::failure(
            projection_finalize_error(finalized, "overlay_journal.history"));
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

std::uint64_t overlay_journal_t::wait_for_publication() const noexcept {
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(250);
    for (;;) {
        const auto epoch = publication_epoch_.load(std::memory_order_acquire);
        if ((epoch & 1U) == 0)
            return epoch;
        if (std::chrono::steady_clock::now() >= deadline)
            return epoch;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

overlay_snapshot_t overlay_journal_t::snapshot() const {
    static_cast<void>(wait_for_publication());
    overlay_snapshot_t result;
    {
        std::shared_lock<std::shared_mutex> lock(state_mutex_);
        result.revision = revision_;
        result.history_cursor = history_cursor_;
        result.history_epoch = history_epoch_;
        result.items.reserve(items_.size());
        for (const auto& item : items_)
            result.items.push_back(item);
    }
    std::sort(result.items.begin(), result.items.end(),
        [](const auto& lhs, const auto& rhs) {
            return lhs.first < rhs.first;
        });
    return result;
}

overlay_history_snapshot_t overlay_journal_t::history_snapshot() const noexcept {
    overlay_history_snapshot_t result;
    std::shared_lock<std::shared_mutex> lock(state_mutex_);
    result.revision = revision_;
    result.history_cursor = history_cursor_;
    result.next_transaction_id = next_transaction_id_;
    result.history_epoch = history_epoch_;
    return result;
}

overlay_target_identity_v9_t overlay_journal_t::fixed_target() const {
    static_cast<void>(wait_for_publication());
    std::shared_lock<std::shared_mutex> lock(state_mutex_);
    return fixed_target_;
}

std::optional<overlay_operation_t> overlay_journal_t::find(
    const std::string& entity) const {
    static_cast<void>(wait_for_publication());
    std::shared_lock<std::shared_mutex> lock(state_mutex_);
    const auto found = items_.find(entity);
    if (found == items_.end())
        return std::nullopt;
    return found->second;
}

std::vector<overlay_operation_t> overlay_journal_t::patch_operations() const {
    static_cast<void>(wait_for_publication());
    std::vector<overlay_operation_t> result;
    {
        std::shared_lock<std::shared_mutex> lock(state_mutex_);
        for (const auto& item : items_) {
            if (item.second.kind == overlay_operation_kind_t::byte_patch ||
                item.second.kind == overlay_operation_kind_t::assembly_patch ||
                item.second.kind == overlay_operation_kind_t::integer_patch)
                result.push_back(item.second);
        }
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
