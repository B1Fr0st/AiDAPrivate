#include "cli_provider.hpp"
#include "../../workspace/byte_provider.hpp"
#include "../../workspace/workspace_identity.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <set>
#include <stdexcept>
#include <string_view>
#include <tuple>
#include <unordered_set>
#include <utility>

namespace aida::analysis::managed_cli {
namespace {

using json = nlohmann::json;

constexpr std::string_view k_schema = "aida.c03.managed-cli.worker";
constexpr std::string_view k_decompiler_package_id = "ICSharpCode.Decompiler";
constexpr std::string_view k_decompiler_package_version = "10.1.0.8386";
constexpr std::string_view k_decompiler_package_file = "ICSharpCode.Decompiler.10.1.0.8386.nupkg";
constexpr std::string_view k_decompiler_package_hash = "a6fb2e9be86c1b73e54231e20640d4d566c52f21cba9ad99c3e9100d67e8f5af";
constexpr std::string_view k_immutable_package_id = "System.Collections.Immutable";
constexpr std::string_view k_immutable_package_version = "9.0.0";
constexpr std::string_view k_immutable_package_file = "System.Collections.Immutable.9.0.0.nupkg";
constexpr std::string_view k_immutable_package_hash = "fbaab954c7a87396e6e1616ca15ea705703d755e696bf3b8c96fa039d8bcc9a7";
constexpr std::string_view k_metadata_package_id = "System.Reflection.Metadata";
constexpr std::string_view k_metadata_package_version = "9.0.0";
constexpr std::string_view k_metadata_package_file = "System.Reflection.Metadata.9.0.0.nupkg";
constexpr std::string_view k_metadata_package_hash = "6af1166dc0a1ed7829b127ac9d1dff4a0c568bfe82e4ec6347cf497ff49f4634";
constexpr std::string_view k_sdk_hash = "a5ccdc3a41d5e5c6014ff64509aed176db39f4f14caffff3dd1997f8907e94d7";
constexpr std::string_view k_decompiler_assembly_hash = "bebc24d573164da41b6f43f521d96362516d0f4b5b2715a9e7d877f4b2730345";
constexpr std::size_t k_max_wire_bytes = 16U << 20;
constexpr std::size_t k_max_source_bytes = 8U << 20;
constexpr std::size_t k_max_token_entries = 1U << 20;
constexpr std::size_t k_max_type_entries = 1U << 20;
constexpr std::size_t k_max_ir_nodes = 1U << 20;

class decode_error_t final : public std::runtime_error {
public:
    explicit decode_error_t(const char* message) : std::runtime_error(message) {}
    explicit decode_error_t(const std::string& message) : std::runtime_error(message) {}
};

workspace_error_t error(workspace_error_code_t code, std::string message, std::string phase)
{
    return make_workspace_error(code, std::move(message), std::move(phase));
}

template <typename T>
workspace_result_t<T> failure(workspace_error_code_t code, std::string message, std::string phase)
{
    return workspace_result_t<T>::failure(error(code, std::move(message), std::move(phase)));
}

bool is_simple_file_name(const std::string& value)
{
    return !value.empty() && value.size() <= 255 && value.find_first_of("\\/:") == std::string::npos &&
        value.find("..") == std::string::npos && std::all_of(value.begin(), value.end(), [](unsigned char character) {
            return std::isalnum(character) != 0 || character == '.' || character == '-' || character == '_';
        });
}

sha256_digest_t digest_from_hex(std::string_view value)
{
    if (value.size() != 64 || !std::all_of(value.begin(), value.end(), [](unsigned char character) {
        return std::isdigit(character) != 0 || (character >= 'a' && character <= 'f');
    }))
        throw decode_error_t("digest is not a lowercase SHA-256 value");
    const auto digest = sha256_digest_t::from_hex(std::string(value));
    if (!digest)
        throw decode_error_t("digest decoding failed");
    return *digest;
}

std::string digest_hex(const sha256_digest_t& value)
{
    return value.to_hex();
}

bool same_digest(const sha256_digest_t& left, const sha256_digest_t& right)
{
    return left.constant_time_equal(right);
}

std::string canonical_lock_text()
{
    return std::string(k_decompiler_package_id) + "|" + std::string(k_decompiler_package_version) + "|" + std::string(k_decompiler_package_hash) + "\n" +
        std::string(k_immutable_package_id) + "|" + std::string(k_immutable_package_version) + "|" + std::string(k_immutable_package_hash) + "\n" +
        std::string(k_metadata_package_id) + "|" + std::string(k_metadata_package_version) + "|" + std::string(k_metadata_package_hash);
}

sha256_digest_t expected_lock_hash()
{
    return stable_serialization_hash(canonical_lock_text());
}

bool matches_locked_packages(const std::vector<offline_package_t>& packages)
{
    const std::array<std::tuple<std::string_view, std::string_view, std::string_view, std::string_view>, 3> expected = {{
        {k_decompiler_package_id, k_decompiler_package_version, k_decompiler_package_file, k_decompiler_package_hash},
        {k_immutable_package_id, k_immutable_package_version, k_immutable_package_file, k_immutable_package_hash},
        {k_metadata_package_id, k_metadata_package_version, k_metadata_package_file, k_metadata_package_hash}
    }};
    if (packages.size() != expected.size())
        return false;
    for (std::size_t index = 0; index < expected.size(); ++index) {
        const auto& package = packages[index];
        const auto& expected_package = expected[index];
        if (std::string_view(package.id) != std::get<0>(expected_package) || std::string_view(package.version) != std::get<1>(expected_package) ||
            std::string_view(package.file_name) != std::get<2>(expected_package) || std::string_view(package.content_hash.to_hex()) != std::get<3>(expected_package))
            return false;
    }
    return true;
}

workspace_result_t<sha256_digest_t> hash_file(const std::string& path, const cancellation_token_t& cancel)
{
    const auto provider = mapped_file_provider_t::open(path);
    if (!provider)
        return workspace_result_t<sha256_digest_t>::failure(provider.error());
    const auto hash = sha256_provider(*provider.value(), cancel);
    if (!hash)
        return hash;
    const auto revalidated = provider.value()->revalidate();
    if (!revalidated)
        return workspace_result_t<sha256_digest_t>::failure(revalidated.error());
    return hash;
}

const json& require_member(const json& object, const char* key)
{
    if (!object.is_object())
        throw decode_error_t("wire value is not an object");
    const auto iterator = object.find(key);
    if (iterator == object.end())
        throw decode_error_t(std::string("wire field is absent: ") + key);
    return *iterator;
}

void require_exact_fields(const json& object, std::initializer_list<const char*> fields)
{
    if (!object.is_object() || object.size() != fields.size())
        throw decode_error_t("wire object field set is invalid");
    for (const char* field : fields)
        static_cast<void>(require_member(object, field));
}

std::string require_string(const json& object, const char* key, std::size_t maximum = 1U << 20)
{
    const auto& value = require_member(object, key);
    if (!value.is_string())
        throw decode_error_t(std::string("wire string is invalid: ") + key);
    const auto result = value.get<std::string>();
    if (result.empty() || result.size() > maximum || result.find('\0') != std::string::npos)
        throw decode_error_t(std::string("wire string bounds are invalid: ") + key);
    return result;
}

std::string require_string_allow_empty(const json& object, const char* key, std::size_t maximum = 1U << 20)
{
    const auto& value = require_member(object, key);
    if (!value.is_string())
        throw decode_error_t(std::string("wire string is invalid: ") + key);
    const auto result = value.get<std::string>();
    if (result.size() > maximum || result.find('\0') != std::string::npos)
        throw decode_error_t(std::string("wire string bounds are invalid: ") + key);
    return result;
}

std::uint64_t require_u64(const json& object, const char* key)
{
    const auto& value = require_member(object, key);
    if (!value.is_number_unsigned())
        throw decode_error_t(std::string("wire unsigned integer is invalid: ") + key);
    return value.get<std::uint64_t>();
}

std::uint32_t require_u32(const json& object, const char* key)
{
    const auto value = require_u64(object, key);
    if (value > (std::numeric_limits<std::uint32_t>::max)())
        throw decode_error_t(std::string("wire u32 is invalid: ") + key);
    return static_cast<std::uint32_t>(value);
}

std::int32_t require_i32(const json& object, const char* key)
{
    const auto& value = require_member(object, key);
    if (!value.is_number_integer())
        throw decode_error_t(std::string("wire signed integer is invalid: ") + key);
    const auto result = value.get<std::int64_t>();
    if (result < (std::numeric_limits<std::int32_t>::min)() || result > (std::numeric_limits<std::int32_t>::max)())
        throw decode_error_t(std::string("wire i32 is invalid: ") + key);
    return static_cast<std::int32_t>(result);
}

bool require_bool(const json& object, const char* key)
{
    const auto& value = require_member(object, key);
    if (!value.is_boolean())
        throw decode_error_t(std::string("wire boolean is invalid: ") + key);
    return value.get<bool>();
}

const json& require_array(const json& object, const char* key, std::size_t maximum)
{
    const auto& result = require_member(object, key);
    if (!result.is_array() || result.size() > maximum)
        throw decode_error_t(std::string("wire array is invalid: ") + key);
    return result;
}

std::string profile_name(decompiler_profile_id_t value)
{
    switch (value) {
    case decompiler_profile_id_t::fast:
        return "fast";
    case decompiler_profile_id_t::balanced:
        return "balanced";
    case decompiler_profile_id_t::thorough:
        return "thorough";
    }
    throw std::invalid_argument("decompiler profile is invalid");
}

std::string type_kind_name(decompiler_type_kind_t value)
{
    switch (value) {
    case decompiler_type_kind_t::unknown: return "unknown";
    case decompiler_type_kind_t::void_type: return "void";
    case decompiler_type_kind_t::boolean: return "boolean";
    case decompiler_type_kind_t::signed_integer: return "signed_integer";
    case decompiler_type_kind_t::unsigned_integer: return "unsigned_integer";
    case decompiler_type_kind_t::floating_point: return "floating_point";
    case decompiler_type_kind_t::pointer: return "pointer";
    case decompiler_type_kind_t::reference: return "reference";
    case decompiler_type_kind_t::array: return "array";
    case decompiler_type_kind_t::vector: return "vector";
    case decompiler_type_kind_t::structure: return "structure";
    case decompiler_type_kind_t::union_type: return "union";
    case decompiler_type_kind_t::enumeration: return "enumeration";
    case decompiler_type_kind_t::function: return "function";
    case decompiler_type_kind_t::class_type: return "class";
    case decompiler_type_kind_t::interface_type: return "interface";
    case decompiler_type_kind_t::generic_parameter: return "generic_parameter";
    case decompiler_type_kind_t::generic_instance: return "generic_instance";
    case decompiler_type_kind_t::managed_by_reference: return "managed_by_reference";
    }
    throw std::invalid_argument("type kind is invalid");
}

decompiler_type_kind_t parse_type_kind(const std::string& value)
{
    const std::array<std::pair<std::string_view, decompiler_type_kind_t>, 19> values = {{
        {"unknown", decompiler_type_kind_t::unknown}, {"void", decompiler_type_kind_t::void_type}, {"boolean", decompiler_type_kind_t::boolean},
        {"signed_integer", decompiler_type_kind_t::signed_integer}, {"unsigned_integer", decompiler_type_kind_t::unsigned_integer},
        {"floating_point", decompiler_type_kind_t::floating_point}, {"pointer", decompiler_type_kind_t::pointer},
        {"reference", decompiler_type_kind_t::reference}, {"array", decompiler_type_kind_t::array}, {"vector", decompiler_type_kind_t::vector},
        {"structure", decompiler_type_kind_t::structure}, {"union", decompiler_type_kind_t::union_type}, {"enumeration", decompiler_type_kind_t::enumeration},
        {"function", decompiler_type_kind_t::function}, {"class", decompiler_type_kind_t::class_type}, {"interface", decompiler_type_kind_t::interface_type},
        {"generic_parameter", decompiler_type_kind_t::generic_parameter}, {"generic_instance", decompiler_type_kind_t::generic_instance},
        {"managed_by_reference", decompiler_type_kind_t::managed_by_reference}
    }};
    for (const auto& entry : values) {
        if (value == entry.first)
            return entry.second;
    }
    throw decode_error_t("wire type kind is invalid");
}

decompiler_type_edge_kind_t parse_type_edge_kind(const std::string& value)
{
    const std::array<std::pair<std::string_view, decompiler_type_edge_kind_t>, 9> values = {{
        {"member", decompiler_type_edge_kind_t::member}, {"base", decompiler_type_edge_kind_t::base},
        {"pointee", decompiler_type_edge_kind_t::pointee}, {"element", decompiler_type_edge_kind_t::element},
        {"return_type", decompiler_type_edge_kind_t::return_type}, {"parameter", decompiler_type_edge_kind_t::parameter},
        {"alias", decompiler_type_edge_kind_t::alias}, {"generic_argument", decompiler_type_edge_kind_t::generic_argument},
        {"constraint", decompiler_type_edge_kind_t::constraint}
    }};
    for (const auto& entry : values) {
        if (value == entry.first)
            return entry.second;
    }
    throw decode_error_t("wire type edge kind is invalid");
}

provider_ir_opcode_t parse_opcode(const std::string& value)
{
    const std::array<std::pair<std::string_view, provider_ir_opcode_t>, 24> values = {{
        {"parameter", provider_ir_opcode_t::parameter}, {"local", provider_ir_opcode_t::local}, {"constant", provider_ir_opcode_t::constant},
        {"copy", provider_ir_opcode_t::copy}, {"unary", provider_ir_opcode_t::unary}, {"binary", provider_ir_opcode_t::binary},
        {"cast", provider_ir_opcode_t::cast}, {"load", provider_ir_opcode_t::load}, {"store", provider_ir_opcode_t::store},
        {"field_load", provider_ir_opcode_t::field_load}, {"field_store", provider_ir_opcode_t::field_store},
        {"array_load", provider_ir_opcode_t::array_load}, {"array_store", provider_ir_opcode_t::array_store}, {"call", provider_ir_opcode_t::call},
        {"indirect_call", provider_ir_opcode_t::indirect_call}, {"phi", provider_ir_opcode_t::phi}, {"branch", provider_ir_opcode_t::branch},
        {"conditional_branch", provider_ir_opcode_t::conditional_branch}, {"switch_branch", provider_ir_opcode_t::switch_branch},
        {"return_value", provider_ir_opcode_t::return_value}, {"throw_value", provider_ir_opcode_t::throw_value},
        {"monitor_enter", provider_ir_opcode_t::monitor_enter}, {"monitor_exit", provider_ir_opcode_t::monitor_exit}, {"unknown", provider_ir_opcode_t::unknown}
    }};
    for (const auto& entry : values) {
        if (value == entry.first)
            return entry.second;
    }
    throw decode_error_t("wire provider IR opcode is invalid");
}

decompiler_unknown_reason_t parse_unknown_reason(const std::string& value)
{
    const std::array<std::pair<std::string_view, decompiler_unknown_reason_t>, 10> values = {{
        {"unsupported_instruction", decompiler_unknown_reason_t::unsupported_instruction}, {"unsupported_metadata", decompiler_unknown_reason_t::unsupported_metadata},
        {"unresolved_reference", decompiler_unknown_reason_t::unresolved_reference}, {"opaque_control_flow", decompiler_unknown_reason_t::opaque_control_flow},
        {"bounded_analysis_limit", decompiler_unknown_reason_t::bounded_analysis_limit}, {"semantic_timeout", decompiler_unknown_reason_t::semantic_timeout},
        {"incomplete_debug_information", decompiler_unknown_reason_t::incomplete_debug_information}, {"conflicting_type_evidence", decompiler_unknown_reason_t::conflicting_type_evidence},
        {"malformed_input", decompiler_unknown_reason_t::malformed_input}, {"provider_abstained", decompiler_unknown_reason_t::provider_abstained}
    }};
    for (const auto& entry : values) {
        if (value == entry.first)
            return entry.second;
    }
    throw decode_error_t("wire unknown reason is invalid");
}

decompiler_fact_provenance_t parse_provenance(const std::string& value)
{
    if (value == "loader_metadata")
        return decompiler_fact_provenance_t::loader_metadata;
    if (value == "provider_semantics")
        return decompiler_fact_provenance_t::provider_semantics;
    throw decode_error_t("wire provenance is invalid");
}

decompiler_diagnostic_severity_t parse_severity(const std::string& value)
{
    if (value == "note") return decompiler_diagnostic_severity_t::note;
    if (value == "warning") return decompiler_diagnostic_severity_t::warning;
    if (value == "error") return decompiler_diagnostic_severity_t::error;
    throw decode_error_t("wire diagnostic severity is invalid");
}

decompiler_diagnostic_code_t parse_diagnostic_code(const std::string& value)
{
    if (value == "invalid_contract") return decompiler_diagnostic_code_t::invalid_contract;
    if (value == "unresolved_reference") return decompiler_diagnostic_code_t::unresolved_symbol;
    if (value == "resource_limit") return decompiler_diagnostic_code_t::resource_limit;
    if (value == "deadline_exceeded") return decompiler_diagnostic_code_t::deadline_exceeded;
    if (value == "cancelled") return decompiler_diagnostic_code_t::cancelled;
    if (value == "malformed_metadata") return decompiler_diagnostic_code_t::malformed_provider_ir;
    if (value == "worker_integrity_failure") return decompiler_diagnostic_code_t::worker_integrity_failure;
    if (value == "provider_failure") return decompiler_diagnostic_code_t::provider_failure;
    throw decode_error_t("wire diagnostic code is invalid");
}

source_coordinate_t provider_coordinate(const request_t& request, std::int32_t offset, std::uint32_t token)
{
    source_coordinate_t result;
    result.layer = decompiler_coordinate_layer_t::provider_ir;
    result.workspace_generation = request.workspace_generation;
    result.entity = request.entity;
    if (token != 0 && token != (std::numeric_limits<std::uint32_t>::max)())
        result.token_range = decompiler_token_range_t{token, token + 1};
    if (offset >= 0) {
        const auto instruction_id = static_cast<std::uint64_t>(offset) + 1;
        result.instruction_range = decompiler_instruction_range_t{instruction_id, instruction_id};
    }
    return result;
}

decompiler_diagnostic_t parse_diagnostic(const json& value, const request_t& request)
{
    require_exact_fields(value, {"severity", "code", "key", "args", "ilOffset", "confidence", "retryable", "ordinal"});
    decompiler_diagnostic_t result;
    result.severity = parse_severity(require_string(value, "severity", 32));
    result.code = parse_diagnostic_code(require_string(value, "code", 64));
    result.localization_key = require_string(value, "key", 256);
    const auto& arguments = require_array(value, "args", 1024);
    for (const auto& argument : arguments) {
        if (!argument.is_string() || argument.get_ref<const std::string&>().size() > 4096)
            throw decode_error_t("wire diagnostic argument is invalid");
        result.localization_arguments.push_back(argument.get<std::string>());
    }
    const auto& offset = require_member(value, "ilOffset");
    if (offset.is_null()) {
    } else if (offset.is_number_integer()) {
        const auto offset_value = require_i32(value, "ilOffset");
        if (offset_value >= 0)
            result.coordinate = provider_coordinate(request, offset_value, 0);
    } else {
        throw decode_error_t("wire diagnostic offset is invalid");
    }
    const auto confidence = require_u64(value, "confidence");
    if (confidence > 100)
        throw decode_error_t("wire diagnostic confidence is invalid");
    result.confidence = static_cast<std::uint8_t>(confidence);
    result.retryable = require_bool(value, "retryable");
    result.ordinal = require_u32(value, "ordinal");
    if (result.ordinal == 0)
        throw decode_error_t("wire diagnostic ordinal is invalid");
    return result;
}

std::vector<decompiler_diagnostic_t> parse_diagnostics(const json& values, const request_t& request)
{
    if (!values.is_array() || values.size() > k_max_ir_nodes)
        throw decode_error_t("wire diagnostics are invalid");
    std::vector<decompiler_diagnostic_t> result;
    result.reserve(values.size());
    std::uint32_t previous = 0;
    for (const auto& value : values) {
        auto diagnostic = parse_diagnostic(value, request);
        if (diagnostic.ordinal <= previous)
            throw decode_error_t("wire diagnostic ordering is invalid");
        previous = diagnostic.ordinal;
        result.push_back(std::move(diagnostic));
    }
    return result;
}

void validate_response_header(const json& value, const request_t& request, const char* kind)
{
    if (std::string_view(require_string(value, "schema", 128)) != k_schema || require_u32(value, "schemaVersion") != k_managed_cli_worker_protocol_version ||
        require_string(value, "kind", 32) != kind || require_u64(value, "sequence") != request.sequence ||
        require_string(value, "requestId", 128) != request.request_id || require_string(value, "moduleHash", 64) != digest_hex(std::get<cli_decompiler_entity_identity_t>(request.entity.identity).module_hash) ||
        require_u32(value, "metadataToken") != std::get<cli_decompiler_entity_identity_t>(request.entity.identity).metadata_token ||
        !same_digest(digest_from_hex(require_string(value, "offlineLockHash", 64)), request.offline_lock_hash))
        throw decode_error_t("worker response header does not match its request");
}

}

workspace_result_t<sha256_digest_t> verify_offline_lock(const offline_lock_t& lock, const cancellation_token_t& cancel)
{
    if (lock.package_root.empty() || lock.sdk_path.empty() || !matches_locked_packages(lock.packages) ||
        std::string_view(lock.sdk_hash.to_hex()) != k_sdk_hash)
        return failure<sha256_digest_t>(workspace_error_code_t::integrity_failure, "managed CLI offline lock is invalid", "managed_cli.lock");
    const auto root = normalize_utf8_path(lock.package_root, true);
    if (!root)
        return workspace_result_t<sha256_digest_t>::failure(root.error());
    const auto sdk = hash_file(lock.sdk_path, cancel);
    if (!sdk)
        return sdk;
    if (!same_digest(sdk.value(), lock.sdk_hash))
        return failure<sha256_digest_t>(workspace_error_code_t::integrity_failure, "managed CLI SDK hash mismatch", "managed_cli.lock");
    for (const auto& package : lock.packages) {
        if (!is_simple_file_name(package.file_name))
            return failure<sha256_digest_t>(workspace_error_code_t::integrity_failure, "managed CLI package name is invalid", "managed_cli.lock");
        const auto path = normalize_utf8_path(root.value() + "\\" + package.file_name, true);
        if (!path)
            return workspace_result_t<sha256_digest_t>::failure(path.error());
        const auto actual = hash_file(path.value(), cancel);
        if (!actual)
            return actual;
        if (!same_digest(actual.value(), package.content_hash))
            return failure<sha256_digest_t>(workspace_error_code_t::integrity_failure, "managed CLI package hash mismatch", "managed_cli.lock");
    }
    return workspace_result_t<sha256_digest_t>::success(expected_lock_hash());
}

workspace_result_t<request_t> make_request(
    std::uint64_t sequence,
    std::string request_id,
    std::string module_path,
    decompiler_entity_key_t entity,
    std::uint64_t workspace_generation,
    decompiler_profile_budget_t profile,
    worker_identity_t worker,
    offline_lock_t offline_lock,
    const cancellation_token_t& cancel)
{
    if (sequence == 0 || request_id.empty() || request_id.size() > 128 || request_id.find('\0') != std::string::npos ||
        module_path.empty() || module_path.size() > 32768 || module_path.find('\0') != std::string::npos ||
        workspace_generation == 0 || std::string_view(worker.provider_version) != k_decompiler_package_version ||
        worker.worker_build_id.empty() || worker.worker_build_id.size() > 256 || worker.worker_build_id.find('\0') != std::string::npos ||
        worker.worker_build_hash.empty())
        return failure<request_t>(workspace_error_code_t::invalid_argument, "managed CLI request identity is invalid", "managed_cli.request");
    const auto verified_lock = verify_offline_lock(offline_lock, cancel);
    if (!verified_lock)
        return workspace_result_t<request_t>::failure(verified_lock.error());
    if (!same_digest(worker.decompiler_assembly_hash, digest_from_hex(k_decompiler_assembly_hash)))
        return failure<request_t>(workspace_error_code_t::integrity_failure, "managed CLI decompiler hash is not locked", "managed_cli.request");
    const auto entity_validation = validate_decompiler_entity_key(entity);
    if (!entity_validation.valid() || entity.kind != decompiler_entity_kind_t::cli_method || !std::holds_alternative<cli_decompiler_entity_identity_t>(entity.identity))
        return failure<request_t>(workspace_error_code_t::invalid_argument, "managed CLI entity is invalid", "managed_cli.request");
    const auto& cli = std::get<cli_decompiler_entity_identity_t>(entity.identity);
    if ((cli.metadata_token >> 24) != 0x06 || (cli.metadata_token & 0x00ffffffU) == 0 || cli.assembly_identity.empty() ||
        cli.module_name.empty() || cli.declaring_type.empty() || cli.method_name.empty() || cli.method_signature.empty())
        return failure<request_t>(workspace_error_code_t::invalid_argument, "managed CLI method token is invalid", "managed_cli.request");
    if (!validate_decompiler_profile(profile).valid())
        return failure<request_t>(workspace_error_code_t::invalid_argument, "managed CLI profile is invalid", "managed_cli.request");
    const auto normalized_module = normalize_utf8_path(module_path, false);
    if (!normalized_module)
        return workspace_result_t<request_t>::failure(normalized_module.error());
    const auto normalized_root = normalize_utf8_path(offline_lock.package_root, true);
    if (!normalized_root)
        return workspace_result_t<request_t>::failure(normalized_root.error());
    const auto normalized_sdk = normalize_utf8_path(offline_lock.sdk_path, true);
    if (!normalized_sdk)
        return workspace_result_t<request_t>::failure(normalized_sdk.error());
    offline_lock.package_root = normalized_root.value();
    offline_lock.sdk_path = normalized_sdk.value();
    request_t result;
    result.sequence = sequence;
    result.request_id = std::move(request_id);
    result.module_path = normalized_module.value();
    result.entity = std::move(entity);
    result.workspace_generation = workspace_generation;
    result.profile = std::move(profile);
    result.worker = std::move(worker);
    result.offline_lock = std::move(offline_lock);
    result.offline_lock_hash = verified_lock.value();
    return workspace_result_t<request_t>::success(std::move(result));
}

workspace_result_t<std::vector<std::string>> make_worker_startup_arguments(
    const request_t& request,
    const cancellation_token_t& cancel)
{
    const auto checked = make_request(request.sequence, request.request_id, request.module_path, request.entity,
        request.workspace_generation, request.profile, request.worker, request.offline_lock, cancel);
    if (!checked)
        return workspace_result_t<std::vector<std::string>>::failure(checked.error());
    return workspace_result_t<std::vector<std::string>>::success(
        std::vector<std::string>{"--offline-package-root", checked.value().offline_lock.package_root});
}

workspace_result_t<std::string> serialize_request(const request_t& request)
{
    const auto checked = make_request(request.sequence, request.request_id, request.module_path, request.entity,
        request.workspace_generation, request.profile, request.worker, request.offline_lock);
    if (!checked)
        return workspace_result_t<std::string>::failure(checked.error());
    const auto& canonical = checked.value();
    const auto& cli = std::get<cli_decompiler_entity_identity_t>(canonical.entity.identity);
    json result;
    result["schema"] = std::string(k_schema);
    result["schemaVersion"] = k_managed_cli_worker_protocol_version;
    result["kind"] = "decompile";
    result["sequence"] = canonical.sequence;
    result["requestId"] = canonical.request_id;
    result["modulePath"] = canonical.module_path;
    result["moduleHash"] = digest_hex(cli.module_hash);
    result["metadataToken"] = cli.metadata_token;
    result["workspaceGeneration"] = canonical.workspace_generation;
    result["offlineLockHash"] = digest_hex(canonical.offline_lock_hash);
    result["budget"] = {
        {"profile", profile_name(canonical.profile.profile)}, {"maxWallClockMs", canonical.profile.max_wall_clock_ms},
        {"maxCpuMs", canonical.profile.max_cpu_ms}, {"maxMemoryBytes", canonical.profile.max_memory_bytes},
        {"maxProviderIrNodes", canonical.profile.max_provider_ir_nodes}
    };
    result["provider"] = {
        {"version", canonical.worker.provider_version}, {"decompilerAssemblyHash", digest_hex(canonical.worker.decompiler_assembly_hash)},
        {"workerBuildId", canonical.worker.worker_build_id}, {"workerBuildHash", digest_hex(canonical.worker.worker_build_hash)}
    };
    return workspace_result_t<std::string>::success(result.dump());
}

workspace_result_t<std::string> serialize_cancellation(const request_t& request, std::uint64_t sequence, std::string stable_reason)
{
    if (sequence == 0 || stable_reason.empty() || stable_reason.size() > 256 || stable_reason.find('\0') != std::string::npos)
        return failure<std::string>(workspace_error_code_t::invalid_argument, "managed CLI cancellation is invalid", "managed_cli.cancel");
    const auto checked = serialize_request(request);
    if (!checked)
        return workspace_result_t<std::string>::failure(checked.error());
    json result;
    result["schema"] = std::string(k_schema);
    result["schemaVersion"] = k_managed_cli_worker_protocol_version;
    result["kind"] = "cancel";
    result["sequence"] = sequence;
    result["requestId"] = request.request_id;
    result["stableReason"] = std::move(stable_reason);
    return workspace_result_t<std::string>::success(result.dump());
}

workspace_result_t<response_t> deserialize_response(const request_t& request, const std::string& payload, const cancellation_token_t& cancel)
{
    const auto checked = make_request(request.sequence, request.request_id, request.module_path, request.entity,
        request.workspace_generation, request.profile, request.worker, request.offline_lock, cancel);
    if (!checked)
        return workspace_result_t<response_t>::failure(checked.error());
    if (cancel.stop_requested())
        return failure<response_t>(cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded : workspace_error_code_t::cancelled,
            "managed CLI response parsing was cancelled", "managed_cli.response");
    if (payload.empty() || payload.size() > k_max_wire_bytes)
        return failure<response_t>(workspace_error_code_t::decode_failure, "managed CLI response size is invalid", "managed_cli.response");
    try {
        const auto envelope = json::parse(payload, nullptr, true, true);
        const auto kind = require_string(envelope, "kind", 32);
        if (kind == "failure") {
            require_exact_fields(envelope, {"schema", "schemaVersion", "kind", "sequence", "requestId", "moduleHash", "metadataToken", "offlineLockHash", "diagnostics"});
            validate_response_header(envelope, request, "failure");
            response_t result;
            result.failure = failure_t{parse_diagnostics(require_array(envelope, "diagnostics", k_max_ir_nodes), request)};
            if (result.failure->diagnostics.empty())
                throw decode_error_t("worker failure has no diagnostic");
            return workspace_result_t<response_t>::success(std::move(result));
        }
        if (kind != "result")
            throw decode_error_t("worker response kind is invalid");
        require_exact_fields(envelope, {"schema", "schemaVersion", "kind", "sequence", "requestId", "moduleHash", "metadataToken", "offlineLockHash", "provider", "identity", "source", "tokenMap", "typeGraph", "ir", "unknowns", "diagnostics"});
        validate_response_header(envelope, request, "result");
        const auto& cli = std::get<cli_decompiler_entity_identity_t>(request.entity.identity);

        const auto& provider = require_member(envelope, "provider");
        require_exact_fields(provider, {"version", "decompilerAssemblyHash"});
        if (require_string(provider, "version", 64) != request.worker.provider_version ||
            !same_digest(digest_from_hex(require_string(provider, "decompilerAssemblyHash", 64)), request.worker.decompiler_assembly_hash))
            throw decode_error_t("worker provider identity does not match its request");

        const auto& identity = require_member(envelope, "identity");
        require_exact_fields(identity, {"assemblyIdentity", "moduleName", "declaringType", "methodName", "methodSignature", "genericArity"});
        if (require_string(identity, "assemblyIdentity", 4096) != cli.assembly_identity || require_string(identity, "moduleName", 4096) != cli.module_name ||
            require_string(identity, "declaringType", 4096) != cli.declaring_type || require_string(identity, "methodName", 4096) != cli.method_name ||
            require_string(identity, "methodSignature", 16384) != cli.method_signature || require_u32(identity, "genericArity") != cli.generic_arity)
            throw decode_error_t("worker metadata identity does not match its request");

        const auto& source = require_member(envelope, "source");
        require_exact_fields(source, {"text", "sha256"});
        const auto source_text = require_string(source, "text", k_max_source_bytes);
        const auto source_hash = digest_from_hex(require_string(source, "sha256", 64));
        if (!same_digest(stable_serialization_hash(source_text), source_hash))
            throw decode_error_t("worker source hash is invalid");

        type_graph_t types;
        types.entity = request.entity;
        const auto& type_graph = require_member(envelope, "typeGraph");
        require_exact_fields(type_graph, {"revision", "nodes", "edges"});
        types.revision = require_u64(type_graph, "revision");
        const auto& nodes = require_array(type_graph, "nodes", k_max_type_entries);
        if (nodes.empty())
            throw decode_error_t("worker type graph is empty");
        std::unordered_set<std::uint64_t> known_type_ids;
        for (const auto& node : nodes) {
            require_exact_fields(node, {"id", "kind", "canonicalName", "displayName", "byteSize", "alignment", "signed", "confidence"});
            decompiler_type_node_t parsed;
            parsed.id = require_u64(node, "id");
            parsed.kind = parse_type_kind(require_string(node, "kind", 64));
            parsed.canonical_name = require_string(node, "canonicalName", 16384);
            parsed.display_name = require_string(node, "displayName", 16384);
            const auto& size = require_member(node, "byteSize");
            if (size.is_null()) {
            } else if (size.is_number_unsigned()) {
                parsed.byte_size = size.get<std::uint64_t>();
            } else {
                throw decode_error_t("worker type byte size is invalid");
            }
            parsed.alignment = require_u32(node, "alignment");
            parsed.is_signed = require_bool(node, "signed");
            const auto confidence = require_u64(node, "confidence");
            if (confidence > 100)
                throw decode_error_t("worker type confidence is invalid");
            parsed.confidence = static_cast<std::uint8_t>(confidence);
            parsed.provenance = decompiler_fact_provenance_t::loader_metadata;
            if (parsed.id == 0 || !known_type_ids.insert(parsed.id).second)
                throw decode_error_t("worker type IDs are invalid");
            types.nodes.push_back(std::move(parsed));
        }
        const auto& edges = require_array(type_graph, "edges", k_max_type_entries);
        for (const auto& edge : edges) {
            require_exact_fields(edge, {"sourceTypeId", "targetTypeId", "kind", "stableName", "byteOffset", "ordinal", "confidence"});
            decompiler_type_edge_t parsed;
            parsed.source_type_id = require_u64(edge, "sourceTypeId");
            parsed.target_type_id = require_u64(edge, "targetTypeId");
            parsed.kind = parse_type_edge_kind(require_string(edge, "kind", 64));
            parsed.stable_name = require_string_allow_empty(edge, "stableName", 16384);
            const auto& offset = require_member(edge, "byteOffset");
            if (offset.is_null()) {
            } else if (offset.is_number_unsigned()) {
                parsed.byte_offset = offset.get<std::uint64_t>();
            } else {
                throw decode_error_t("worker type edge offset is invalid");
            }
            parsed.ordinal = require_u32(edge, "ordinal");
            const auto confidence = require_u64(edge, "confidence");
            if (confidence > 100)
                throw decode_error_t("worker type edge confidence is invalid");
            parsed.confidence = static_cast<std::uint8_t>(confidence);
            parsed.provenance = decompiler_fact_provenance_t::loader_metadata;
            types.edges.push_back(std::move(parsed));
        }

        provider_ir_t ir;
        ir.provider.provider = decompiler_provider_id_t::ilspy_cli;
        ir.provider.provider_name = "ICSharpCode.Decompiler";
        ir.provider.provider_version = request.worker.provider_version;
        ir.provider.provider_binary_hash = request.worker.decompiler_assembly_hash;
        ir.provider.worker_build_id = request.worker.worker_build_id;
        ir.provider.worker_build_hash = request.worker.worker_build_hash;
        ir.language.language_id = "cli-il";
        ir.language.language_version = "ecma-335";
        ir.language.compiler_spec_id = "managed-cli";
        ir.language.language_spec_hash = stable_serialization_hash(std::string("cli-il|ecma-335|") + request.worker.provider_version);
        ir.entity = request.entity;
        const auto& wire_ir = require_member(envelope, "ir");
        require_exact_fields(wire_ir, {"entryBlockId", "blocks"});
        ir.entry_block_id = require_u64(wire_ir, "entryBlockId");
        const auto& blocks = require_array(wire_ir, "blocks", k_max_ir_nodes);
        if (blocks.empty())
            throw decode_error_t("worker provider IR is empty");
        std::size_t value_count = 0;
        std::unordered_set<std::uint64_t> known_value_ids;
        for (const auto& block : blocks) {
            if (cancel.stop_requested())
                throw decode_error_t("worker response parsing was cancelled");
            require_exact_fields(block, {"id", "predecessorIds", "successorIds", "exceptionSuccessorIds", "values", "startOffset"});
            provider_ir_block_t parsed;
            parsed.id = require_u64(block, "id");
            const auto parse_ids = [](const json& values) {
                if (!values.is_array() || values.size() > k_max_ir_nodes)
                    throw decode_error_t("worker provider IR edge list is invalid");
                std::vector<std::uint64_t> result;
                result.reserve(values.size());
                for (const auto& value : values) {
                    if (!value.is_number_unsigned())
                        throw decode_error_t("worker provider IR edge value is invalid");
                    result.push_back(value.get<std::uint64_t>());
                }
                return result;
            };
            parsed.predecessor_ids = parse_ids(require_array(block, "predecessorIds", k_max_ir_nodes));
            parsed.successor_ids = parse_ids(require_array(block, "successorIds", k_max_ir_nodes));
            parsed.exception_successor_ids = parse_ids(require_array(block, "exceptionSuccessorIds", k_max_ir_nodes));
            const auto start_offset = require_i32(block, "startOffset");
            parsed.coordinate = provider_coordinate(request, start_offset, cli.metadata_token);
            const auto& values = require_array(block, "values", k_max_ir_nodes);
            value_count += values.size();
            if (value_count > k_max_ir_nodes || value_count > request.profile.max_provider_ir_nodes)
                throw decode_error_t("worker provider IR node limit is exceeded");
            for (const auto& value : values) {
                require_exact_fields(value, {"id", "opcode", "typeId", "operandIds", "stableImmediate", "stableSymbol", "ilOffset", "metadataToken", "confidence", "provenance"});
                provider_ir_value_t node;
                node.id = require_u64(value, "id");
                if (node.id == 0 || !known_value_ids.insert(node.id).second)
                    throw decode_error_t("worker provider IR value IDs are invalid");
                node.opcode = parse_opcode(require_string(value, "opcode", 64));
                node.type_id = require_u64(value, "typeId");
                if (known_type_ids.find(node.type_id) == known_type_ids.end())
                    throw decode_error_t("worker provider IR references an unknown type");
                node.operand_ids = parse_ids(require_array(value, "operandIds", k_max_ir_nodes));
                node.stable_immediate = require_string_allow_empty(value, "stableImmediate", 16384);
                node.stable_symbol = require_string_allow_empty(value, "stableSymbol", 16384);
                const auto offset = require_i32(value, "ilOffset");
                node.coordinate = provider_coordinate(request, offset, require_u32(value, "metadataToken"));
                const auto confidence = require_u64(value, "confidence");
                if (confidence > 100)
                    throw decode_error_t("worker provider IR node confidence is invalid");
                node.confidence = static_cast<std::uint8_t>(confidence);
                node.provenance = parse_provenance(require_string(value, "provenance", 64));
                parsed.values.push_back(std::move(node));
            }
            ir.blocks.push_back(std::move(parsed));
        }
        for (const auto& block : ir.blocks) {
            for (const auto& node : block.values) {
                if (!std::all_of(node.operand_ids.begin(), node.operand_ids.end(), [&known_value_ids](std::uint64_t operand_id) {
                    return operand_id != 0 && known_value_ids.find(operand_id) != known_value_ids.end();
                }))
                    throw decode_error_t("worker provider IR references an unknown operand value");
            }
        }

        const auto& wire_unknowns = require_array(envelope, "unknowns", k_max_ir_nodes);
        for (const auto& value : wire_unknowns) {
            require_exact_fields(value, {"reason", "stableToken", "ilOffset", "metadataToken", "confidence", "provenance"});
            decompiler_unknown_t unknown;
            unknown.reason = parse_unknown_reason(require_string(value, "reason", 64));
            unknown.stable_token = require_string(value, "stableToken", 16384);
            unknown.coordinate = provider_coordinate(request, require_i32(value, "ilOffset"), require_u32(value, "metadataToken"));
            const auto confidence = require_u64(value, "confidence");
            if (confidence > 100)
                throw decode_error_t("worker unknown confidence is invalid");
            unknown.confidence = static_cast<std::uint8_t>(confidence);
            unknown.provenance = parse_provenance(require_string(value, "provenance", 64));
            ir.unknowns.push_back(std::move(unknown));
        }
        ir.diagnostics = parse_diagnostics(require_array(envelope, "diagnostics", k_max_ir_nodes), request);

        const auto& wire_tokens = require_array(envelope, "tokenMap", k_max_token_entries);
        if (wire_tokens.empty())
            throw decode_error_t("worker token map is empty");
        std::vector<token_map_entry_t> token_map;
        token_map.reserve(wire_tokens.size());
        std::uint32_t previous_token = 0;
        for (const auto& value : wire_tokens) {
            require_exact_fields(value, {"token", "stableIdentity", "declaringType", "methodName", "methodSignature", "genericArity", "isAsync", "isIterator", "hasExceptionRegions"});
            token_map_entry_t entry;
            entry.metadata_token = require_u32(value, "token");
            if ((entry.metadata_token >> 24) != 0x06 || entry.metadata_token <= previous_token)
                throw decode_error_t("worker token map ordering is invalid");
            previous_token = entry.metadata_token;
            entry.stable_identity = require_string(value, "stableIdentity", 32768);
            entry.declaring_type = require_string(value, "declaringType", 4096);
            entry.method_name = require_string(value, "methodName", 4096);
            entry.method_signature = require_string(value, "methodSignature", 16384);
            entry.generic_arity = require_u32(value, "genericArity");
            entry.is_async = require_bool(value, "isAsync");
            entry.is_iterator = require_bool(value, "isIterator");
            entry.has_exception_regions = require_bool(value, "hasExceptionRegions");
            token_map.push_back(std::move(entry));
        }
        const auto token = std::find_if(token_map.begin(), token_map.end(), [&cli](const token_map_entry_t& entry) { return entry.metadata_token == cli.metadata_token; });
        if (token == token_map.end() || token->declaring_type != cli.declaring_type || token->method_name != cli.method_name ||
            token->method_signature != cli.method_signature || token->generic_arity != cli.generic_arity)
            throw decode_error_t("worker token map does not contain the requested method");

        const auto type_validation = validate_type_graph(types);
        const auto ir_validation = validate_provider_ir(ir);
        if (!type_validation.valid() || !ir_validation.valid())
            throw decode_error_t("worker typed provider IR violates the C03 contract");
        auto diagnostics = ir.diagnostics;
        response_t result;
        result.analysis = analysis_t{std::move(ir), std::move(types), source_text, source_hash, std::move(token_map), std::move(diagnostics)};
        return workspace_result_t<response_t>::success(std::move(result));
    } catch (const decode_error_t& exception) {
        return failure<response_t>(workspace_error_code_t::decode_failure, exception.what(), "managed_cli.response");
    } catch (const json::exception& exception) {
        return failure<response_t>(workspace_error_code_t::decode_failure, exception.what(), "managed_cli.response");
    } catch (const std::exception& exception) {
        return failure<response_t>(workspace_error_code_t::decode_failure, exception.what(), "managed_cli.response");
    }
}

}
