#include "benchmark_sla_schema.hpp"
#include "evidence_hash.hpp"

#include "../../src/core/analysis/benchmark/benchmark_sla.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <map>
#include <set>
#include <string_view>
#include <vector>

namespace aida::analysis::c03
{
namespace
{
bool is_sha256(const json& value)
{
    if (!value.is_string() || value.get_ref<const std::string&>().size() != 64)
        return false;
    const auto& digest = value.get_ref<const std::string&>();
    if (std::all_of(digest.begin(), digest.end(), [](unsigned char ch) { return ch == '0'; }))
        return false;
    return std::all_of(digest.begin(), digest.end(), [](unsigned char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
}

bool is_nonempty_string(const json& value)
{
    return value.is_string() && !value.get_ref<const std::string&>().empty();
}

bool is_nonnegative_integer(const json& value)
{
    return value.is_number_unsigned() || (value.is_number_integer() && value.get<std::int64_t>() >= 0);
}

bool is_nonnegative_number(const json& value)
{
    return value.is_number() && std::isfinite(value.get<double>()) && value.get<double>() >= 0.0;
}

const json* require_field(contract_validation_result_t& result, const json& object,
    std::string_view path, std::string_view name)
{
    if (!object.is_object()) {
        result.reject(std::string(path), "object_required", "expected an object");
        return nullptr;
    }
    const auto it = object.find(std::string(name));
    if (it == object.end()) {
        result.reject(std::string(path) + "/" + std::string(name), "required", "field is required");
        return nullptr;
    }
    return &*it;
}

void require_closed_object(contract_validation_result_t& result, const json& object,
    std::string_view path, std::initializer_list<std::string_view> allowed)
{
    if (!object.is_object()) {
        result.reject(std::string(path), "object_required", "expected an object");
        return;
    }
    std::set<std::string, std::less<>> names;
    for (const std::string_view name : allowed)
        names.emplace(name);
    for (auto it = object.begin(); it != object.end(); ++it) {
        if (names.find(it.key()) == names.end())
            result.reject(std::string(path) + "/" + it.key(), "additional_property", "field is not allowed");
    }
}

bool require_string(contract_validation_result_t& result, const json& object,
    std::string_view path, std::string_view name)
{
    const json* value = require_field(result, object, path, name);
    if (!value)
        return false;
    if (!is_nonempty_string(*value)) {
        result.reject(std::string(path) + "/" + std::string(name), "string_required",
            "expected a non-empty string");
        return false;
    }
    return true;
}

bool require_sha256(contract_validation_result_t& result, const json& object,
    std::string_view path, std::string_view name)
{
    const json* value = require_field(result, object, path, name);
    if (!value)
        return false;
    if (!is_sha256(*value)) {
        result.reject(std::string(path) + "/" + std::string(name), "sha256_required",
            "expected a non-zero lowercase SHA-256 digest");
        return false;
    }
    return true;
}

bool require_bool(contract_validation_result_t& result, const json& object,
    std::string_view path, std::string_view name, bool expected)
{
    const json* value = require_field(result, object, path, name);
    if (!value)
        return false;
    if (!value->is_boolean() || value->get<bool>() != expected) {
        result.reject(std::string(path) + "/" + std::string(name), "boolean_value",
            expected ? "expected true" : "expected false");
        return false;
    }
    return true;
}

bool require_positive_integer(contract_validation_result_t& result, const json& object,
    std::string_view path, std::string_view name)
{
    const json* value = require_field(result, object, path, name);
    if (!value)
        return false;
    if (!is_nonnegative_integer(*value) || value->get<std::uint64_t>() == 0) {
        result.reject(std::string(path) + "/" + std::string(name), "positive_integer_required",
            "expected a positive integer");
        return false;
    }
    return true;
}

bool require_nonnegative_integer(contract_validation_result_t& result, const json& object,
    std::string_view path, std::string_view name)
{
    const json* value = require_field(result, object, path, name);
    if (!value)
        return false;
    if (!is_nonnegative_integer(*value)) {
        result.reject(std::string(path) + "/" + std::string(name), "nonnegative_integer_required",
            "expected a non-negative integer");
        return false;
    }
    return true;
}

bool require_nonnegative_number(contract_validation_result_t& result, const json& object,
    std::string_view path, std::string_view name)
{
    const json* value = require_field(result, object, path, name);
    if (!value)
        return false;
    if (!is_nonnegative_number(*value)) {
        result.reject(std::string(path) + "/" + std::string(name), "nonnegative_number_required",
            "expected a finite non-negative number");
        return false;
    }
    return true;
}

double nearest_rank_p95(std::vector<double> values)
{
    if (values.empty())
        return 0.0;
    std::sort(values.begin(), values.end());
    const std::size_t rank = static_cast<std::size_t>(std::ceil(static_cast<double>(values.size()) * 0.95));
    return values[std::max<std::size_t>(1, rank) - 1];
}

double median(std::vector<double> values)
{
    if (values.empty())
        return 0.0;
    std::sort(values.begin(), values.end());
    const std::size_t middle = values.size() / 2;
    if (values.size() % 2 != 0)
        return values[middle];
    return (values[middle - 1] + values[middle]) / 2.0;
}

bool has_exact_thresholds(const json& value)
{
    const json& expected = benchmark_sla_thresholds();
    if (!value.is_object() || value.size() != expected.size())
        return false;
    for (auto it = expected.begin(); it != expected.end(); ++it) {
        const auto actual = value.find(it.key());
        if (actual == value.end() || *actual != *it)
            return false;
    }
    return true;
}

bool add_without_overflow(std::uint64_t& aggregate, std::uint64_t value)
{
    if (value > (std::numeric_limits<std::uint64_t>::max)() - aggregate)
        return false;
    aggregate += value;
    return true;
}

void validate_evidence_bindings(contract_validation_result_t& result, const json& bindings,
    std::map<std::string, std::string, std::less<>>& binding_hashes)
{
    if (!bindings.is_array()) {
        result.reject("/provenance/evidence_bindings", "array_required", "expected an array");
        return;
    }
    if (bindings.empty())
        result.reject("/provenance/evidence_bindings", "min_items", "benchmark file evidence bindings are required");
    for (std::size_t index = 0; index < bindings.size(); ++index) {
        const auto& binding = bindings[index];
        const std::string path = "/provenance/evidence_bindings/" + std::to_string(index);
        require_closed_object(result, binding, path, {"id", "kind", "path", "sha256", "max_bytes"});
        const bool id_valid = require_string(result, binding, path, "id");
        require_string(result, binding, path, "kind");
        if (require_string(result, binding, path, "path")) {
            const auto value = binding.at("path").get<std::string>();
            if (value.find("..") != std::string::npos || (!value.empty() && (value.front() == '/' || value.front() == '\\')) ||
                value.find(':') != std::string::npos)
                result.reject(path + "/path", "path_scope", "evidence binding path must be repository-relative");
        }
        const bool hash_valid = require_sha256(result, binding, path, "sha256");
        const json* max_bytes = require_field(result, binding, path, "max_bytes");
        if (max_bytes && (!is_nonnegative_integer(*max_bytes) || max_bytes->get<std::uint64_t>() == 0 ||
            max_bytes->get<std::uint64_t>() > 4ULL * 1024ULL * 1024ULL * 1024ULL))
            result.reject(path + "/max_bytes", "bounded_positive_integer_required", "evidence byte limit is invalid");
        if (id_valid && hash_valid && !binding_hashes.emplace(binding.at("id").get<std::string>(),
            binding.at("sha256").get<std::string>()).second)
            result.reject(path + "/id", "duplicate_binding", "evidence binding identifier is duplicated");
    }
}

void validate_bound_hash(contract_validation_result_t& result,
    const std::map<std::string, std::string, std::less<>>& bindings,
    const json& object, std::string_view path, std::string_view binding_name, std::string_view hash_name)
{
    const bool binding_valid = require_string(result, object, path, binding_name);
    const bool hash_valid = require_sha256(result, object, path, hash_name);
    if (!binding_valid || !hash_valid)
        return;
    const auto binding = bindings.find(object.at(std::string(binding_name)).get<std::string>());
    if (binding == bindings.end() || binding->second != object.at(std::string(hash_name)).get<std::string>())
        result.reject(std::string(path) + "/" + std::string(binding_name), "binding_hash_mismatch",
            "declared digest does not match its file evidence binding");
}

void validate_matrix(contract_validation_result_t& result, const json& matrix, std::string_view path)
{
    require_closed_object(result, matrix, path,
        {"formats", "architectures", "entries"});
    const json* formats = require_field(result, matrix, path, "formats");
    const json* architectures = require_field(result, matrix, path, "architectures");
    const json* entries = require_field(result, matrix, path, "entries");
    std::set<std::string, std::less<>> format_set;
    std::set<std::string, std::less<>> architecture_set;
    const auto parse_names = [&result](const json* values, const std::string& value_path,
                                      std::set<std::string, std::less<>>& destination) {
        if (!values || !values->is_array()) {
            if (values)
                result.reject(value_path, "array_required", "expected an array");
            return;
        }
        if (values->empty())
            result.reject(value_path, "min_items", "matrix values are required");
        for (std::size_t index = 0; index < values->size(); ++index) {
            if (!is_nonempty_string((*values)[index])) {
                result.reject(value_path + "/" + std::to_string(index), "string_required", "expected a non-empty string");
                continue;
            }
            if (!destination.insert((*values)[index].get<std::string>()).second)
                result.reject(value_path + "/" + std::to_string(index), "duplicate", "duplicate matrix value");
        }
    };
    parse_names(formats, std::string(path) + "/formats", format_set);
    parse_names(architectures, std::string(path) + "/architectures", architecture_set);
    if (!entries || !entries->is_array()) {
        if (entries)
            result.reject(std::string(path) + "/entries", "array_required", "expected an array");
        return;
    }
    if (entries->empty())
        result.reject(std::string(path) + "/entries", "min_items", "matrix entries are required");
    for (std::size_t index = 0; index < entries->size(); ++index) {
        const auto& entry = (*entries)[index];
        const std::string entry_path = std::string(path) + "/entries/" + std::to_string(index);
        require_closed_object(result, entry, entry_path, {"format", "architecture", "mode", "endian"});
        for (const std::string_view field : {"format", "architecture", "mode", "endian"})
            require_string(result, entry, entry_path, field);
        if (entry.contains("format") && is_nonempty_string(entry.at("format")) &&
            format_set.find(entry.at("format").get<std::string>()) == format_set.end())
            result.reject(entry_path + "/format", "matrix_format_missing", "format is absent from declared matrix");
        if (entry.contains("architecture") && is_nonempty_string(entry.at("architecture")) &&
            architecture_set.find(entry.at("architecture").get<std::string>()) == architecture_set.end())
            result.reject(entry_path + "/architecture", "matrix_architecture_missing", "architecture is absent from declared matrix");
    }
}
}

const json& benchmark_sla_thresholds()
{
    const auto& program = aida::analysis::benchmark::program_sla_thresholds();
    static const json thresholds = {
        {"threshold_schema", "aida.c03.benchmark-sla-thresholds"},
        {"threshold_schema_version", 2},
        {"release_min_artifact_bytes", aida::analysis::benchmark::real_fixture_min_bytes},
        {"release_max_artifact_bytes", aida::analysis::benchmark::real_fixture_max_bytes},
        {"required_min_samples", 5},
        {"cancellation_p95_ms_max", program["cancellation_p95_ms_max"].get<double>()},
        {"metadata_ready_ms_max", program["metadata_ready_ms_max"].get<double>()},
        {"warm_reopen_ms_max", program["warm_reopen_ms_max"].get<double>()},
        {"indexed_query_p95_ms_max", program["indexed_query_p95_ms_max"].get<double>()},
        {"warm_analysis_p50_ms_max", 60000.0},
        {"warm_analysis_max_ms_max", 75000.0},
        {"incremental_private_bytes_max",
            program["incremental_private_bytes_max"].get<std::uint64_t>()},
        {"resident_bytes_max", 8589934592ULL},
        {"workspace_mapped_bytes_max",
            program["workspace_mapped_bytes_max"].get<std::uint64_t>()},
        {"global_mapped_bytes_max",
            program["global_mapped_bytes_max"].get<std::uint64_t>()},
        {"cache_bytes_max", 1073741824ULL},
        {"spill_bytes_max", 1073741824ULL},
        {"spill_written_total_bytes_max", 4294967296ULL},
        {"spill_read_total_bytes_max", 4294967296ULL},
        {"minimum_concurrent_workspaces", 2},
        {"queue_wait_ms_max", 1000.0},
        {"no_progress_ms_max", 2000.0},
        {"heartbeat_gap_ms_max", 1000.0}
    };
    return thresholds;
}

const json& approved_external_sla_slot()
{
    static const json slot = {
        {"schema", "aida.c03.external-sla-slot"},
        {"schema_version", 2},
        {"slot_id", "c03-release-sla-300-500mb"},
        {"tier", "release_sla_external"},
        {"approval", {
            {"approval_id", "aida.c03.release-sla.external-slot.2026-07-12.v1"},
            {"policy_version", 1}, {"status", "approved"}}},
        {"generator_source", {
            {"path", "src/standalone/tests/c03/fixtures/external_sla_qualification_policy.json"},
            {"sha256", "72670c1cf56cc13252aa63dff99337e0bf1fd7c7c60ca286c1468941092e306b"}}},
        {"license", {
            {"policy_id", "aida.c03.license-clean-redistributable.v1"},
            {"policy_version", 1},
            {"allowed_spdx", {"CC0-1.0", "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Zlib"}},
            {"redistribution_required", true}}},
        {"size_bytes", {{"minimum", 300000000ULL}, {"maximum", 500000000ULL}}},
        {"receipt_requirements", {
            {"artifact_sha256", true}, {"source_provenance", true}, {"license", true}, {"hardware", true},
            {"cache", true}, {"matrix", true}, {"raw_samples", true}, {"resource_quotas", true},
            {"pressure_telemetry", true}, {"slot_binding", true}}}
    };
    return slot;
}

const json& benchmark_sla_receipt_schema()
{
    static const json schema = json::parse(R"schema({
        "$id":"aida.c03.benchmark-sla-receipt.v2",
        "type":"object",
        "required":["schema","schema_version","receipt_id","mode","claim_status","provenance","thresholds","receipt_sha256"],
        "additionalProperties":false,
        "properties":{
            "schema":{"const":"aida.c03.benchmark-sla-receipt"},
            "schema_version":{"const":2},
            "receipt_id":{"type":"string","minLength":1},
            "mode":{"enum":["deterministic_component","release_sla"]},
            "claim_status":{"enum":["development_only","measured","NOT RUN - NO QUALIFYING LOCAL FIXTURE"]},
            "provenance":{"type":"object"},
            "corpus":{"type":"object"},
            "matrix":{"type":"object"},
            "hardware":{"type":"object"},
            "cache":{"type":"object"},
            "resource_quotas":{"type":"object"},
            "sample_policy":{"type":"object"},
            "samples":{"type":"array","minItems":1},
            "aggregate":{"type":"object"},
            "thresholds":{"type":"object"},
            "external_slot":{"type":"object"},
            "not_run":{"type":"object"},
            "receipt_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}
        },
        "oneOf":[
            {"required":["corpus","matrix","hardware","cache","resource_quotas","sample_policy","samples","aggregate"],
             "not":{"anyOf":[{"required":["external_slot"]},{"required":["not_run"]}]},
             "anyOf":[
                 {"properties":{"mode":{"const":"deterministic_component"},"claim_status":{"const":"development_only"}}},
                 {"properties":{"mode":{"const":"release_sla"},"claim_status":{"const":"measured"}}}
             ]},
            {"required":["external_slot","not_run"],
             "properties":{"mode":{"const":"release_sla"},"claim_status":{"const":"NOT RUN - NO QUALIFYING LOCAL FIXTURE"}},
             "not":{"anyOf":[{"required":["corpus"]},{"required":["matrix"]},{"required":["hardware"]},
                 {"required":["cache"]},{"required":["resource_quotas"]},{"required":["sample_policy"]},
                 {"required":["samples"]},{"required":["aggregate"]}]}}
        ]
    })schema");
    return schema;
}

contract_validation_result_t validate_external_sla_slot(const json& slot)
{
    contract_validation_result_t result;
    require_closed_object(result, slot, "",
        {"schema", "schema_version", "slot_id", "tier", "approval", "generator_source", "license", "size_bytes", "receipt_requirements"});
    if (require_string(result, slot, "", "schema") && slot.at("schema") != "aida.c03.external-sla-slot")
        result.reject("/schema", "schema_id", "unexpected external SLA slot schema identifier");
    const json* version = require_field(result, slot, "", "schema_version");
    if (version && (!version->is_number_integer() || version->get<std::int64_t>() != 2))
        result.reject("/schema_version", "schema_version", "expected schema version 2");
    if (require_string(result, slot, "", "slot_id") &&
        slot.at("slot_id") != approved_external_sla_slot().at("slot_id"))
        result.reject("/slot_id", "unapproved_external_slot", "slot identifier is not approved for release evidence");
    if (require_string(result, slot, "", "tier") && slot.at("tier").get<std::string>() != "release_sla_external")
        result.reject("/tier", "tier", "external slot must be reserved for release SLA evidence");
    const json* approval = require_field(result, slot, "", "approval");
    if (approval) {
        require_closed_object(result, *approval, "/approval", {"approval_id", "policy_version", "status"});
        if (require_string(result, *approval, "/approval", "approval_id") &&
            approval->at("approval_id") != approved_external_sla_slot().at("approval").at("approval_id"))
            result.reject("/approval/approval_id", "slot_approval_mismatch", "slot approval identifier is not approved");
        const bool approval_policy_version_valid = require_positive_integer(result, *approval, "/approval", "policy_version");
        if (approval_policy_version_valid &&
            approval->at("policy_version") != approved_external_sla_slot().at("approval").at("policy_version")) {
            result.reject("/approval/policy_version", "slot_policy_version", "slot policy version is not approved");
        }
        if (require_string(result, *approval, "/approval", "status") && approval->at("status") != "approved")
            result.reject("/approval/status", "slot_approval_status", "slot is not approved for release evidence");
    }
    const json* generator = require_field(result, slot, "", "generator_source");
    if (generator) {
        require_closed_object(result, *generator, "/generator_source", {"path", "sha256"});
        require_string(result, *generator, "/generator_source", "path");
        require_sha256(result, *generator, "/generator_source", "sha256");
    }
    const json* license = require_field(result, slot, "", "license");
    if (license) {
        require_closed_object(result, *license, "/license",
            {"policy_id", "policy_version", "allowed_spdx", "redistribution_required"});
        if (require_string(result, *license, "/license", "policy_id") &&
            license->at("policy_id") != approved_external_sla_slot().at("license").at("policy_id"))
            result.reject("/license/policy_id", "license_policy_mismatch", "slot license policy is not approved");
        const bool license_policy_version_valid = require_positive_integer(result, *license, "/license", "policy_version");
        if (license_policy_version_valid &&
            license->at("policy_version") != approved_external_sla_slot().at("license").at("policy_version")) {
            result.reject("/license/policy_version", "license_policy_version", "slot license policy version is not approved");
        }
        const json* allowed_spdx = require_field(result, *license, "/license", "allowed_spdx");
        if (allowed_spdx && *allowed_spdx != approved_external_sla_slot().at("license").at("allowed_spdx"))
            result.reject("/license/allowed_spdx", "license_policy_mismatch", "slot license allow-list is not approved");
        require_bool(result, *license, "/license", "redistribution_required", true);
    }
    const json* size = require_field(result, slot, "", "size_bytes");
    if (size) {
        require_closed_object(result, *size, "/size_bytes", {"minimum", "maximum"});
        require_positive_integer(result, *size, "/size_bytes", "minimum");
        require_positive_integer(result, *size, "/size_bytes", "maximum");
        if (size->contains("minimum") && size->at("minimum") != benchmark_sla_thresholds().at("release_min_artifact_bytes"))
            result.reject("/size_bytes/minimum", "size_policy", "release minimum must be exactly 300 MB");
        if (size->contains("maximum") && size->at("maximum") != benchmark_sla_thresholds().at("release_max_artifact_bytes"))
            result.reject("/size_bytes/maximum", "size_policy", "release maximum must be exactly 500 MB");
    }
    const json* requirements = require_field(result, slot, "", "receipt_requirements");
    if (requirements) {
        require_closed_object(result, *requirements, "/receipt_requirements",
            {"artifact_sha256", "source_provenance", "license", "hardware", "cache", "matrix", "raw_samples",
             "resource_quotas", "pressure_telemetry", "slot_binding"});
        for (const std::string_view field : {"artifact_sha256", "source_provenance", "license", "hardware", "cache", "matrix", "raw_samples",
                 "resource_quotas", "pressure_telemetry", "slot_binding"})
            require_bool(result, *requirements, "/receipt_requirements", field, true);
    }
    if (slot != approved_external_sla_slot())
        result.reject("", "unapproved_external_slot", "external slot must exactly match the approved release policy");
    return result;
}

contract_validation_result_t validate_benchmark_sla_receipt(const json& receipt)
{
    return validate_benchmark_sla_receipt(receipt, approved_external_sla_slot());
}

contract_validation_result_t validate_benchmark_sla_receipt(const json& receipt,
    const json& approved_external_slot)
{
    contract_validation_result_t result;
    require_closed_object(result, receipt, "",
        {"schema", "schema_version", "receipt_id", "mode", "claim_status", "provenance", "corpus", "matrix",
         "hardware", "cache", "resource_quotas", "sample_policy", "samples", "aggregate", "thresholds",
         "external_slot", "not_run", "receipt_sha256"});
    if (require_string(result, receipt, "", "schema") && receipt.at("schema") != "aida.c03.benchmark-sla-receipt")
        result.reject("/schema", "schema_id", "unexpected benchmark SLA receipt schema identifier");
    const json* version = require_field(result, receipt, "", "schema_version");
    if (version && (!version->is_number_integer() || version->get<std::int64_t>() != 2))
        result.reject("/schema_version", "schema_version", "expected schema version 2");
    require_string(result, receipt, "", "receipt_id");
    require_sha256(result, receipt, "", "receipt_sha256");

    bool release_sla = false;
    bool not_run = false;
    bool approved_slot_valid = true;
    if (require_string(result, receipt, "", "mode")) {
        const auto mode = receipt.at("mode").get<std::string>();
        if (mode != "deterministic_component" && mode != "release_sla")
            result.reject("/mode", "unsupported_mode", "unsupported benchmark mode");
        release_sla = mode == "release_sla";
    }
    if (release_sla) {
        const auto slot_validation = validate_external_sla_slot(approved_external_slot);
        approved_slot_valid = slot_validation.valid;
        for (const auto& violation : slot_validation.violations)
            result.reject("/approved_external_slot" + violation.path, violation.code, violation.message);
    }
    if (require_string(result, receipt, "", "claim_status")) {
        const auto claim_status = receipt.at("claim_status").get<std::string>();
        not_run = release_sla && claim_status == "NOT RUN - NO QUALIFYING LOCAL FIXTURE";
        if ((release_sla && claim_status != "measured" && !not_run) || (!release_sla && claim_status != "development_only"))
            result.reject("/claim_status", "claim_status", "claim status does not match benchmark mode");
    }

    if (not_run) {
        require_closed_object(result, receipt, "",
            {"schema", "schema_version", "receipt_id", "mode", "claim_status", "provenance", "external_slot",
             "not_run", "thresholds", "receipt_sha256"});
        const json* provenance = require_field(result, receipt, "", "provenance");
        std::map<std::string, std::string, std::less<>> binding_hashes;
        if (provenance) {
            require_closed_object(result, *provenance, "/provenance",
                {"authorization_id", "harness_build_sha256", "runtime_build_sha256", "manifest_sha256",
                 "policy_sha256", "harness_binding_id", "runtime_binding_id", "manifest_binding_id",
                 "policy_binding_id", "evidence_bindings"});
            require_string(result, *provenance, "/provenance", "authorization_id");
            const json* bindings = require_field(result, *provenance, "/provenance", "evidence_bindings");
            if (bindings)
                validate_evidence_bindings(result, *bindings, binding_hashes);
            validate_bound_hash(result, binding_hashes, *provenance, "/provenance",
                "harness_binding_id", "harness_build_sha256");
            validate_bound_hash(result, binding_hashes, *provenance, "/provenance",
                "runtime_binding_id", "runtime_build_sha256");
            validate_bound_hash(result, binding_hashes, *provenance, "/provenance",
                "manifest_binding_id", "manifest_sha256");
            validate_bound_hash(result, binding_hashes, *provenance, "/provenance",
                "policy_binding_id", "policy_sha256");
            if (provenance->contains("policy_sha256") && is_sha256(provenance->at("policy_sha256")) &&
                provenance->at("policy_sha256") != approved_external_sla_slot().at("generator_source").at("sha256"))
                result.reject("/provenance/policy_sha256", "source_provenance_mismatch",
                    "not-run evidence does not bind the approved qualification policy");
        }
        const json* slot = require_field(result, receipt, "", "external_slot");
        if (slot) {
            const auto slot_result = validate_external_sla_slot(*slot);
            for (const auto& violation : slot_result.violations)
                result.reject("/external_slot" + violation.path, violation.code, violation.message);
        }
        const json* reason = require_field(result, receipt, "", "not_run");
        if (reason) {
            require_closed_object(result, *reason, "/not_run",
                {"reason", "searched_roots", "candidate_count", "rejection_evidence", "target_execution_forbidden"});
            if (require_string(result, *reason, "/not_run", "reason") &&
                reason->at("reason") != "NO QUALIFYING LOCAL FIXTURE")
                result.reject("/not_run/reason", "not_run_reason", "not-run reason must be exact and truthful");
            const json* roots = require_field(result, *reason, "/not_run", "searched_roots");
            if (!roots || !roots->is_array() || roots->empty())
                result.reject("/not_run/searched_roots", "min_items", "searched local roots are required");
            require_nonnegative_integer(result, *reason, "/not_run", "candidate_count");
            const json* rejections = require_field(result, *reason, "/not_run", "rejection_evidence");
            if (!rejections || !rejections->is_array())
                result.reject("/not_run/rejection_evidence", "array_required", "candidate rejection evidence is required");
            else if (reason->contains("candidate_count") && is_nonnegative_integer(reason->at("candidate_count")) &&
                reason->at("candidate_count").get<std::uint64_t>() != rejections->size())
                result.reject("/not_run/candidate_count", "candidate_count_mismatch",
                    "candidate count must equal the rejection evidence cardinality");
            require_bool(result, *reason, "/not_run", "target_execution_forbidden", true);
        }
        const json* thresholds = require_field(result, receipt, "", "thresholds");
        if (thresholds && !has_exact_thresholds(*thresholds))
            result.reject("/thresholds", "threshold_drift", "receipt thresholds must equal the C03 SLA contract");
        std::string receipt_hash_error;
        if (!verify_canonical_receipt_hash(receipt, "receipt_sha256", receipt_hash_error))
            result.reject("/receipt_sha256", "receipt_hash", receipt_hash_error);
        return result;
    }

    const json* provenance = require_field(result, receipt, "", "provenance");
    std::map<std::string, std::string, std::less<>> binding_hashes;
    if (provenance) {
        require_closed_object(result, *provenance, "/provenance",
            {"authorization_id", "harness_build_sha256", "runtime_build_sha256", "manifest_sha256",
             "harness_binding_id", "runtime_binding_id", "manifest_binding_id", "evidence_bindings"});
        require_string(result, *provenance, "/provenance", "authorization_id");
        const json* bindings = require_field(result, *provenance, "/provenance", "evidence_bindings");
        if (bindings)
            validate_evidence_bindings(result, *bindings, binding_hashes);
        validate_bound_hash(result, binding_hashes, *provenance, "/provenance",
            "harness_binding_id", "harness_build_sha256");
        validate_bound_hash(result, binding_hashes, *provenance, "/provenance",
            "runtime_binding_id", "runtime_build_sha256");
        validate_bound_hash(result, binding_hashes, *provenance, "/provenance",
            "manifest_binding_id", "manifest_sha256");
    }

    const json* corpus = require_field(result, receipt, "", "corpus");
    if (corpus) {
        require_closed_object(result, *corpus, "/corpus",
            {"external_slot_id", "slot_approval_id", "license_policy_id", "license_policy_version", "artifact", "license",
             "source_provenance_sha256", "source_binding_id"});
        const bool slot_id_valid = require_string(result, *corpus, "/corpus", "external_slot_id");
        const bool approval_id_valid = require_string(result, *corpus, "/corpus", "slot_approval_id");
        const bool license_policy_id_valid = require_string(result, *corpus, "/corpus", "license_policy_id");
        const bool license_policy_version_valid = require_positive_integer(result, *corpus, "/corpus", "license_policy_version");
        const bool source_provenance_valid = require_sha256(result, *corpus, "/corpus", "source_provenance_sha256");
        const bool source_binding_valid = require_string(result, *corpus, "/corpus", "source_binding_id");
        if (source_binding_valid && source_provenance_valid) {
            const auto binding = binding_hashes.find(corpus->at("source_binding_id").get<std::string>());
            if (binding == binding_hashes.end() || binding->second != corpus->at("source_provenance_sha256").get<std::string>())
                result.reject("/corpus/source_binding_id", "binding_hash_mismatch",
                    "corpus provenance does not match its file evidence binding");
        }
        if (release_sla && approved_slot_valid && slot_id_valid && corpus->at("external_slot_id") != approved_external_slot.at("slot_id"))
            result.reject("/corpus/external_slot_id", "unapproved_external_slot", "receipt does not bind the approved external slot");
        if (release_sla && approved_slot_valid && approval_id_valid &&
            corpus->at("slot_approval_id") != approved_external_slot.at("approval").at("approval_id"))
            result.reject("/corpus/slot_approval_id", "slot_approval_mismatch", "receipt approval does not bind the approved slot");
        if (release_sla && approved_slot_valid && license_policy_id_valid &&
            corpus->at("license_policy_id") != approved_external_slot.at("license").at("policy_id"))
            result.reject("/corpus/license_policy_id", "license_policy_mismatch", "receipt license policy is not approved");
        if (release_sla && approved_slot_valid && license_policy_version_valid &&
            corpus->at("license_policy_version") != approved_external_slot.at("license").at("policy_version"))
            result.reject("/corpus/license_policy_version", "license_policy_version", "receipt license policy version is not approved");
        if (release_sla && approved_slot_valid && source_provenance_valid &&
            corpus->at("source_provenance_sha256") != approved_external_slot.at("generator_source").at("sha256"))
            result.reject("/corpus/source_provenance_sha256", "source_provenance_mismatch",
                "receipt provenance does not bind the approved slot generator");
        const json* artifact = require_field(result, *corpus, "/corpus", "artifact");
        if (artifact) {
            require_closed_object(result, *artifact, "/corpus/artifact",
                {"sha256", "size_bytes", "format", "architecture", "mode", "endian", "external", "binding_id", "qualification"});
            require_sha256(result, *artifact, "/corpus/artifact", "sha256");
            require_positive_integer(result, *artifact, "/corpus/artifact", "size_bytes");
            for (const std::string_view field : {"format", "architecture", "mode", "endian"})
                require_string(result, *artifact, "/corpus/artifact", field);
            require_bool(result, *artifact, "/corpus/artifact", "external", release_sla);
            const bool artifact_binding_valid = require_string(result, *artifact, "/corpus/artifact", "binding_id");
            if (artifact_binding_valid && artifact->contains("sha256") && is_sha256(artifact->at("sha256"))) {
                const auto binding = binding_hashes.find(artifact->at("binding_id").get<std::string>());
                if (binding == binding_hashes.end() || binding->second != artifact->at("sha256").get<std::string>())
                    result.reject("/corpus/artifact/binding_id", "binding_hash_mismatch",
                        "artifact digest does not match its file evidence binding");
            }
            const json* qualification = require_field(result, *artifact, "/corpus/artifact", "qualification");
            if (qualification) {
                require_closed_object(result, *qualification, "/corpus/artifact/qualification",
                    {"classification", "production_identity", "version", "executable_bytes", "zero_bytes",
                     "code_density", "zero_ratio", "pdb", "static_library", "installer_only", "fabricated",
                     "code_image", "target_execution_forbidden"});
                for (const std::string_view field : {"classification", "production_identity", "version"})
                    require_string(result, *qualification, "/corpus/artifact/qualification", field);
                for (const std::string_view field : {"executable_bytes", "zero_bytes"})
                    require_nonnegative_integer(result, *qualification, "/corpus/artifact/qualification", field);
                for (const std::string_view field : {"code_density", "zero_ratio"}) {
                    const json* ratio = require_field(result, *qualification, "/corpus/artifact/qualification", field);
                    if (ratio && (!is_nonnegative_number(*ratio) || ratio->get<double>() > 1.0))
                        result.reject("/corpus/artifact/qualification/" + std::string(field), "ratio_required", "expected a finite ratio");
                }
                for (const std::string_view field : {"pdb", "static_library", "installer_only", "fabricated"})
                    require_bool(result, *qualification, "/corpus/artifact/qualification", field, false);
                require_bool(result, *qualification, "/corpus/artifact/qualification", "code_image", true);
                require_bool(result, *qualification, "/corpus/artifact/qualification", "target_execution_forbidden", true);
                if (release_sla) {
                    if (qualification->value("classification", std::string{}) != "production_code_image")
                        result.reject("/corpus/artifact/qualification/classification", "release_fixture_classification",
                            "release SLA requires a production code image");
                    if (qualification->value("executable_bytes", 0ULL) < 64ULL * 1024ULL * 1024ULL)
                        result.reject("/corpus/artifact/qualification/executable_bytes", "release_executable_volume",
                            "release SLA requires at least 64 MiB of executable bytes");
                    if (qualification->value("code_density", 0.0) < 0.10)
                        result.reject("/corpus/artifact/qualification/code_density", "release_code_density",
                            "release SLA fixture code density is too low");
                    if (qualification->value("zero_ratio", 1.0) > 0.80)
                        result.reject("/corpus/artifact/qualification/zero_ratio", "release_zero_padding",
                            "release SLA fixture is dominated by zero padding");
                }
            }
            if (release_sla && artifact->contains("size_bytes") && is_nonnegative_integer(artifact->at("size_bytes"))) {
                const auto size = artifact->at("size_bytes").get<std::uint64_t>();
                const auto minimum = benchmark_sla_thresholds().at("release_min_artifact_bytes").get<std::uint64_t>();
                const auto maximum = benchmark_sla_thresholds().at("release_max_artifact_bytes").get<std::uint64_t>();
                if (size < minimum || size > maximum)
                    result.reject("/corpus/artifact/size_bytes", "sla_artifact_size", "release SLA evidence requires a 300-500 MB artifact");
            }
        }
        const json* license = require_field(result, *corpus, "/corpus", "license");
        if (license) {
            require_closed_object(result, *license, "/corpus/license", {"spdx", "redistribution"});
            const bool spdx_valid = require_string(result, *license, "/corpus/license", "spdx");
            require_bool(result, *license, "/corpus/license", "redistribution", true);
            if (release_sla && approved_slot_valid && spdx_valid) {
                const auto& allowed_spdx = approved_external_slot.at("license").at("allowed_spdx");
                const auto spdx = license->at("spdx").get<std::string>();
                bool allowed = false;
                for (const auto& allowed_spdx_value : allowed_spdx) {
                    if (is_nonempty_string(allowed_spdx_value) && allowed_spdx_value.get<std::string>() == spdx) {
                        allowed = true;
                        break;
                    }
                }
                if (!allowed)
                    result.reject("/corpus/license/spdx", "license_not_allowed", "artifact license is absent from the approved slot policy");
            }
        }
    }

    const json* matrix = require_field(result, receipt, "", "matrix");
    if (matrix)
        validate_matrix(result, *matrix, "/matrix");

    const json* hardware = require_field(result, receipt, "", "hardware");
    if (hardware) {
        require_closed_object(result, *hardware, "/hardware",
            {"cpu_model", "logical_processors", "ram_bytes", "os_build", "storage_model", "storage_bus"});
        for (const std::string_view field : {"cpu_model", "os_build", "storage_model", "storage_bus"})
            require_string(result, *hardware, "/hardware", field);
        for (const std::string_view field : {"logical_processors", "ram_bytes"})
            require_positive_integer(result, *hardware, "/hardware", field);
    }

    const json* cache = require_field(result, receipt, "", "cache");
    if (cache) {
        require_closed_object(result, *cache, "/cache",
            {"disclosure_complete", "os_file_cache", "workspace_database", "provider_cache", "spill_cache"});
        require_bool(result, *cache, "/cache", "disclosure_complete", true);
        const std::set<std::string, std::less<>> states{"cold", "warm", "cleared", "not_applicable"};
        for (const std::string_view field : {"os_file_cache", "workspace_database", "provider_cache", "spill_cache"}) {
            if (require_string(result, *cache, "/cache", field) &&
                states.find(cache->at(std::string(field)).get<std::string>()) == states.end())
                result.reject("/cache/" + std::string(field), "cache_state", "unreported or unsupported cache state");
        }
    }

    const json* resource_quotas = require_field(result, receipt, "", "resource_quotas");
    if (resource_quotas) {
        require_closed_object(result, *resource_quotas, "/resource_quotas", {"cache_bytes_max", "spill_bytes_max"});
        const bool cache_quota_valid = require_positive_integer(result, *resource_quotas, "/resource_quotas", "cache_bytes_max");
        const bool spill_quota_valid = require_positive_integer(result, *resource_quotas, "/resource_quotas", "spill_bytes_max");
        if (cache_quota_valid && resource_quotas->at("cache_bytes_max") != benchmark_sla_thresholds().at("cache_bytes_max"))
            result.reject("/resource_quotas/cache_bytes_max", "quota_drift", "cache quota must equal the C03 SLA contract");
        if (spill_quota_valid && resource_quotas->at("spill_bytes_max") != benchmark_sla_thresholds().at("spill_bytes_max"))
            result.reject("/resource_quotas/spill_bytes_max", "quota_drift", "spill quota must equal the C03 SLA contract");
    }

    std::uint64_t required_samples = 0;
    const json* policy = require_field(result, receipt, "", "sample_policy");
    if (policy) {
        require_closed_object(result, *policy, "/sample_policy", {"required_samples", "sampling_method"});
        if (require_positive_integer(result, *policy, "/sample_policy", "required_samples")) {
            required_samples = policy->at("required_samples").get<std::uint64_t>();
            const auto minimum = benchmark_sla_thresholds().at("required_min_samples").get<std::uint64_t>();
            if (required_samples < minimum)
                result.reject("/sample_policy/required_samples", "sample_count_policy", "sample count is below SLA minimum");
        }
        require_string(result, *policy, "/sample_policy", "sampling_method");
    }

    std::vector<double> warm_analysis;
    std::vector<double> all_cancellation;
    std::vector<double> all_query;
    std::vector<double> all_metadata;
    std::vector<double> warm_reopen;
    std::uint64_t private_peak = 0;
    std::uint64_t resident_peak = 0;
    std::uint64_t workspace_mapped_peak = 0;
    std::uint64_t global_mapped_peak = 0;
    std::uint64_t cache_peak = 0;
    std::uint64_t spill_peak = 0;
    std::uint64_t spill_written_total = 0;
    std::uint64_t spill_read_total = 0;
    std::set<std::string, std::less<>> sample_cache_states;
    const json* samples = require_field(result, receipt, "", "samples");
    if (samples && samples->is_array()) {
        if (required_samples != 0 && samples->size() < required_samples)
            result.reject("/samples", "sample_count", "raw sample count is below declared requirement");
        if (samples->empty())
            result.reject("/samples", "min_items", "raw samples are required");
        std::set<std::string, std::less<>> sample_ids;
        for (std::size_t index = 0; index < samples->size(); ++index) {
            const auto& sample = (*samples)[index];
            const std::string path = "/samples/" + std::to_string(index);
            require_closed_object(result, sample, path,
                {"sample_id", "cache_state", "analysis_ms", "metadata_ready_ms", "warm_reopen_ms", "query_ms",
                 "cancellation_response_ms", "memory", "heartbeats", "concurrent_workspaces"});
            if (require_string(result, sample, path, "sample_id") &&
                !sample_ids.insert(sample.at("sample_id").get<std::string>()).second)
                result.reject(path + "/sample_id", "duplicate", "sample identifier is duplicated");
            if (require_string(result, sample, path, "cache_state")) {
                const auto state = sample.at("cache_state").get<std::string>();
                if (state != "cold" && state != "warm")
                    result.reject(path + "/cache_state", "cache_state", "raw sample cache state must be cold or warm");
                else
                    sample_cache_states.insert(state);
            }
            for (const std::string_view field : {"analysis_ms", "metadata_ready_ms", "warm_reopen_ms", "query_ms", "cancellation_response_ms"})
                require_nonnegative_number(result, sample, path, field);
            if (sample.contains("analysis_ms") && is_nonnegative_number(sample.at("analysis_ms")) &&
                sample.contains("cache_state") && sample.at("cache_state") == "warm")
                warm_analysis.push_back(sample.at("analysis_ms").get<double>());
            if (sample.contains("cancellation_response_ms") && is_nonnegative_number(sample.at("cancellation_response_ms")))
                all_cancellation.push_back(sample.at("cancellation_response_ms").get<double>());
            if (sample.contains("query_ms") && is_nonnegative_number(sample.at("query_ms")))
                all_query.push_back(sample.at("query_ms").get<double>());
            if (sample.contains("metadata_ready_ms") && is_nonnegative_number(sample.at("metadata_ready_ms")))
                all_metadata.push_back(sample.at("metadata_ready_ms").get<double>());
            if (sample.contains("warm_reopen_ms") && is_nonnegative_number(sample.at("warm_reopen_ms")))
                warm_reopen.push_back(sample.at("warm_reopen_ms").get<double>());
            const json* memory = require_field(result, sample, path, "memory");
            if (memory) {
                require_closed_object(result, *memory, path + "/memory",
                    {"private_bytes", "resident_bytes", "workspace_mapped_bytes", "global_mapped_bytes", "cache_bytes",
                     "spill_bytes", "spill_written_bytes", "spill_read_bytes"});
                for (const std::string_view field : {"private_bytes", "resident_bytes", "workspace_mapped_bytes", "global_mapped_bytes"})
                    require_positive_integer(result, *memory, path + "/memory", field);
                for (const std::string_view field : {"cache_bytes", "spill_bytes", "spill_written_bytes", "spill_read_bytes"})
                    require_nonnegative_integer(result, *memory, path + "/memory", field);
                if (memory->contains("private_bytes") && is_nonnegative_integer(memory->at("private_bytes")))
                    private_peak = std::max(private_peak, memory->at("private_bytes").get<std::uint64_t>());
                if (memory->contains("resident_bytes") && is_nonnegative_integer(memory->at("resident_bytes")))
                    resident_peak = std::max(resident_peak, memory->at("resident_bytes").get<std::uint64_t>());
                if (memory->contains("workspace_mapped_bytes") && is_nonnegative_integer(memory->at("workspace_mapped_bytes")))
                    workspace_mapped_peak = std::max(workspace_mapped_peak, memory->at("workspace_mapped_bytes").get<std::uint64_t>());
                if (memory->contains("global_mapped_bytes") && is_nonnegative_integer(memory->at("global_mapped_bytes")))
                    global_mapped_peak = std::max(global_mapped_peak, memory->at("global_mapped_bytes").get<std::uint64_t>());
                if (memory->contains("cache_bytes") && is_nonnegative_integer(memory->at("cache_bytes")))
                    cache_peak = std::max(cache_peak, memory->at("cache_bytes").get<std::uint64_t>());
                if (memory->contains("spill_bytes") && is_nonnegative_integer(memory->at("spill_bytes")))
                    spill_peak = std::max(spill_peak, memory->at("spill_bytes").get<std::uint64_t>());
                for (const auto& field : std::array<std::pair<std::string_view, std::uint64_t*>, 2>{
                         std::pair<std::string_view, std::uint64_t*>{"spill_written_bytes", &spill_written_total},
                         {"spill_read_bytes", &spill_read_total}}) {
                    if (memory->contains(std::string(field.first)) && is_nonnegative_integer(memory->at(std::string(field.first))) &&
                        !add_without_overflow(*field.second, memory->at(std::string(field.first)).get<std::uint64_t>()))
                        result.reject(path + "/memory/" + std::string(field.first), "aggregate_overflow",
                            "spill aggregate exceeds the supported integer range");
                }
                if (resource_quotas && resource_quotas->is_object()) {
                    if (memory->contains("cache_bytes") && is_nonnegative_integer(memory->at("cache_bytes")) &&
                        resource_quotas->contains("cache_bytes_max") && is_nonnegative_integer(resource_quotas->at("cache_bytes_max")) &&
                        memory->at("cache_bytes").get<std::uint64_t>() > resource_quotas->at("cache_bytes_max").get<std::uint64_t>())
                        result.reject(path + "/memory/cache_bytes", "cache_quota_exceeded", "sample cache usage exceeds the declared quota");
                    if (memory->contains("spill_bytes") && is_nonnegative_integer(memory->at("spill_bytes")) &&
                        resource_quotas->contains("spill_bytes_max") && is_nonnegative_integer(resource_quotas->at("spill_bytes_max")) &&
                        memory->at("spill_bytes").get<std::uint64_t>() > resource_quotas->at("spill_bytes_max").get<std::uint64_t>())
                        result.reject(path + "/memory/spill_bytes", "spill_quota_exceeded", "sample spill usage exceeds the declared quota");
                }
            }
            const json* heartbeats = require_field(result, sample, path, "heartbeats");
            if (heartbeats) {
                require_closed_object(result, *heartbeats, path + "/heartbeats",
                    {"ui_count", "security_count", "ui_max_gap_ms", "security_max_gap_ms"});
                require_positive_integer(result, *heartbeats, path + "/heartbeats", "ui_count");
                require_positive_integer(result, *heartbeats, path + "/heartbeats", "security_count");
                for (const std::string_view field : {"ui_max_gap_ms", "security_max_gap_ms"}) {
                    const bool valid = require_nonnegative_number(result, *heartbeats, path + "/heartbeats", field);
                    if (valid && heartbeats->at(std::string(field)).get<double>() >
                        benchmark_sla_thresholds().at("heartbeat_gap_ms_max").get<double>())
                        result.reject(path + "/heartbeats/" + std::string(field), "heartbeat_gap_exceeded",
                            "heartbeat gap exceeds the C03 SLA contract");
                }
            }
            const json* pressure = require_field(result, sample, path, "concurrent_workspaces");
            if (pressure) {
                const std::string pressure_path = path + "/concurrent_workspaces";
                require_closed_object(result, *pressure, pressure_path, {"active", "started", "completed", "fairness"});
                const bool active_valid = require_positive_integer(result, *pressure, pressure_path, "active");
                const bool started_valid = require_positive_integer(result, *pressure, pressure_path, "started");
                const bool completed_valid = require_positive_integer(result, *pressure, pressure_path, "completed");
                if (active_valid && pressure->at("active").get<std::uint64_t>() <
                    benchmark_sla_thresholds().at("minimum_concurrent_workspaces").get<std::uint64_t>())
                    result.reject(pressure_path + "/active", "concurrent_pressure_insufficient",
                        "sample does not exercise the required concurrent workspace pressure");
                if (active_valid && started_valid && pressure->at("started").get<std::uint64_t>() < pressure->at("active").get<std::uint64_t>())
                    result.reject(pressure_path + "/started", "concurrent_accounting_mismatch",
                        "started workspaces are fewer than the concurrently active workspaces");
                if (started_valid && completed_valid && pressure->at("started").get<std::uint64_t>() != pressure->at("completed").get<std::uint64_t>())
                    result.reject(pressure_path + "/completed", "concurrent_accounting_mismatch",
                        "every started workspace must complete during no-starvation evidence");
                const json* fairness = require_field(result, *pressure, pressure_path, "fairness");
                if (fairness) {
                    const std::string fairness_path = pressure_path + "/fairness";
                    require_closed_object(result, *fairness, fairness_path,
                        {"starvation_detected", "max_queue_wait_ms", "max_no_progress_ms", "service_rounds", "per_workspace"});
                    require_bool(result, *fairness, fairness_path, "starvation_detected", false);
                    for (const std::string_view field : {"max_queue_wait_ms", "max_no_progress_ms"}) {
                        const bool valid = require_nonnegative_number(result, *fairness, fairness_path, field);
                        const std::string_view limit = field == "max_queue_wait_ms" ? "queue_wait_ms_max" : "no_progress_ms_max";
                        if (valid && fairness->at(std::string(field)).get<double>() >
                            benchmark_sla_thresholds().at(std::string(limit)).get<double>())
                            result.reject(fairness_path + "/" + std::string(field), "starvation_threshold_exceeded",
                                "concurrent progress exceeds the C03 no-starvation threshold");
                    }
                    const bool rounds_valid = require_positive_integer(result, *fairness, fairness_path, "service_rounds");
                    if (rounds_valid && active_valid && fairness->at("service_rounds").get<std::uint64_t>() < pressure->at("active").get<std::uint64_t>())
                        result.reject(fairness_path + "/service_rounds", "fairness_rounds_insufficient",
                            "service rounds do not cover all concurrently active workspaces");
                    const json* per_workspace = require_field(result, *fairness, fairness_path, "per_workspace");
                    if (per_workspace && per_workspace->is_array()) {
                        std::set<std::string, std::less<>> workspace_ids;
                        if (started_valid && per_workspace->size() != pressure->at("started").get<std::uint64_t>())
                            result.reject(fairness_path + "/per_workspace", "fairness_workspace_coverage",
                                "fairness evidence must cover every started workspace");
                        for (std::size_t workspace_index = 0; workspace_index < per_workspace->size(); ++workspace_index) {
                            const auto& workspace = (*per_workspace)[workspace_index];
                            const std::string workspace_path = fairness_path + "/per_workspace/" + std::to_string(workspace_index);
                            require_closed_object(result, workspace, workspace_path,
                                {"workspace_id", "completed_units", "max_wait_ms"});
                            if (require_string(result, workspace, workspace_path, "workspace_id") &&
                                !workspace_ids.insert(workspace.at("workspace_id").get<std::string>()).second)
                                result.reject(workspace_path + "/workspace_id", "duplicate", "workspace fairness evidence is duplicated");
                            require_positive_integer(result, workspace, workspace_path, "completed_units");
                            const bool wait_valid = require_nonnegative_number(result, workspace, workspace_path, "max_wait_ms");
                            if (wait_valid && workspace.at("max_wait_ms").get<double>() >
                                benchmark_sla_thresholds().at("queue_wait_ms_max").get<double>())
                                result.reject(workspace_path + "/max_wait_ms", "starvation_threshold_exceeded",
                                    "workspace wait exceeds the C03 no-starvation threshold");
                        }
                    } else if (per_workspace) {
                        result.reject(fairness_path + "/per_workspace", "array_required", "expected an array");
                    }
                }
            }
        }
        if (sample_cache_states.find("cold") == sample_cache_states.end() || sample_cache_states.find("warm") == sample_cache_states.end())
            result.reject("/samples", "cache_coverage", "both cold and warm raw samples are required");
    } else if (samples) {
        result.reject("/samples", "array_required", "expected an array");
    }

    const json* aggregate = require_field(result, receipt, "", "aggregate");
    if (aggregate) {
        require_closed_object(result, *aggregate, "/aggregate",
            {"warm_analysis_p50_ms", "warm_analysis_max_ms", "metadata_ready_max_ms", "warm_reopen_max_ms",
             "indexed_query_p95_ms", "cancellation_p95_ms", "private_peak_bytes", "workspace_mapped_peak_bytes",
             "global_mapped_peak_bytes", "resident_peak_bytes", "cache_peak_bytes", "spill_peak_bytes",
             "spill_written_total_bytes", "spill_read_total_bytes"});
        for (const std::string_view field : {"warm_analysis_p50_ms", "warm_analysis_max_ms", "metadata_ready_max_ms",
                 "warm_reopen_max_ms", "indexed_query_p95_ms", "cancellation_p95_ms"})
            require_nonnegative_number(result, *aggregate, "/aggregate", field);
        for (const std::string_view field : {"private_peak_bytes", "workspace_mapped_peak_bytes", "global_mapped_peak_bytes", "resident_peak_bytes"})
            require_positive_integer(result, *aggregate, "/aggregate", field);
        for (const std::string_view field : {"cache_peak_bytes", "spill_peak_bytes", "spill_written_total_bytes", "spill_read_total_bytes"})
            require_nonnegative_integer(result, *aggregate, "/aggregate", field);
        const auto compare_measurement = [&result, aggregate](std::string_view field, double expected) {
            if (aggregate->contains(std::string(field)) && is_nonnegative_number(aggregate->at(std::string(field))) &&
                std::fabs(aggregate->at(std::string(field)).get<double>() - expected) > 1e-9)
                result.reject("/aggregate/" + std::string(field), "aggregate_mismatch", "aggregate disagrees with raw samples");
        };
        compare_measurement("warm_analysis_p50_ms", median(warm_analysis));
        compare_measurement("warm_analysis_max_ms", warm_analysis.empty() ? 0.0 : *std::max_element(warm_analysis.begin(), warm_analysis.end()));
        compare_measurement("metadata_ready_max_ms", all_metadata.empty() ? 0.0 : *std::max_element(all_metadata.begin(), all_metadata.end()));
        compare_measurement("warm_reopen_max_ms", warm_reopen.empty() ? 0.0 : *std::max_element(warm_reopen.begin(), warm_reopen.end()));
        compare_measurement("indexed_query_p95_ms", nearest_rank_p95(all_query));
        compare_measurement("cancellation_p95_ms", nearest_rank_p95(all_cancellation));
        const auto compare_peak = [&result, aggregate](std::string_view field, std::uint64_t expected) {
            if (aggregate->contains(std::string(field)) && is_nonnegative_integer(aggregate->at(std::string(field))) &&
                aggregate->at(std::string(field)).get<std::uint64_t>() != expected)
                result.reject("/aggregate/" + std::string(field), "aggregate_mismatch", "peak disagrees with raw samples");
        };
        compare_peak("private_peak_bytes", private_peak);
        compare_peak("workspace_mapped_peak_bytes", workspace_mapped_peak);
        compare_peak("global_mapped_peak_bytes", global_mapped_peak);
        compare_peak("resident_peak_bytes", resident_peak);
        compare_peak("cache_peak_bytes", cache_peak);
        compare_peak("spill_peak_bytes", spill_peak);
        compare_peak("spill_written_total_bytes", spill_written_total);
        compare_peak("spill_read_total_bytes", spill_read_total);
    }

    const json* thresholds = require_field(result, receipt, "", "thresholds");
    if (thresholds && !has_exact_thresholds(*thresholds))
        result.reject("/thresholds", "threshold_drift", "receipt thresholds must equal the C03 SLA contract");
    if (release_sla && aggregate && aggregate->is_object()) {
        const json& limits = benchmark_sla_thresholds();
        const auto fail_if_exceeds = [&result, aggregate, &limits](std::string_view field, std::string_view limit_field) {
            if (aggregate->contains(std::string(field)) && is_nonnegative_number(aggregate->at(std::string(field))) &&
                aggregate->at(std::string(field)).get<double>() > limits.at(std::string(limit_field)).get<double>())
                result.reject("/aggregate/" + std::string(field), "sla_threshold_exceeded", "SLA threshold exceeded");
        };
        fail_if_exceeds("warm_analysis_p50_ms", "warm_analysis_p50_ms_max");
        fail_if_exceeds("warm_analysis_max_ms", "warm_analysis_max_ms_max");
        fail_if_exceeds("metadata_ready_max_ms", "metadata_ready_ms_max");
        fail_if_exceeds("warm_reopen_max_ms", "warm_reopen_ms_max");
        fail_if_exceeds("indexed_query_p95_ms", "indexed_query_p95_ms_max");
        fail_if_exceeds("cancellation_p95_ms", "cancellation_p95_ms_max");
        const auto fail_if_peak_exceeds = [&result, aggregate, &limits](std::string_view field, std::string_view limit_field) {
            if (aggregate->contains(std::string(field)) && is_nonnegative_integer(aggregate->at(std::string(field))) &&
                aggregate->at(std::string(field)).get<std::uint64_t>() > limits.at(std::string(limit_field)).get<std::uint64_t>())
                result.reject("/aggregate/" + std::string(field), "sla_memory_limit_exceeded", "SLA memory threshold exceeded");
        };
        fail_if_peak_exceeds("private_peak_bytes", "incremental_private_bytes_max");
        fail_if_peak_exceeds("resident_peak_bytes", "resident_bytes_max");
        fail_if_peak_exceeds("workspace_mapped_peak_bytes", "workspace_mapped_bytes_max");
        fail_if_peak_exceeds("global_mapped_peak_bytes", "global_mapped_bytes_max");
        fail_if_peak_exceeds("cache_peak_bytes", "cache_bytes_max");
        fail_if_peak_exceeds("spill_peak_bytes", "spill_bytes_max");
        fail_if_peak_exceeds("spill_written_total_bytes", "spill_written_total_bytes_max");
        fail_if_peak_exceeds("spill_read_total_bytes", "spill_read_total_bytes_max");
    }
    std::string receipt_hash_error;
    if (!verify_canonical_receipt_hash(receipt, "receipt_sha256", receipt_hash_error))
        result.reject("/receipt_sha256", "receipt_hash", receipt_hash_error);
    return result;
}

contract_validation_result_t validate_benchmark_sla_receipt_files(const json& receipt,
    const json& approved_external_slot, const std::filesystem::path& evidence_root)
{
    auto result = validate_benchmark_sla_receipt(receipt, approved_external_slot);
    if (!receipt.is_object() || !receipt.contains("provenance") || !receipt.at("provenance").is_object() ||
        !receipt.at("provenance").contains("evidence_bindings") ||
        !receipt.at("provenance").at("evidence_bindings").is_array())
        return result;
    const auto& bindings = receipt.at("provenance").at("evidence_bindings");
    for (std::size_t index = 0; index < bindings.size(); ++index) {
        const auto& binding = bindings[index];
        if (!binding.is_object() || !binding.contains("path") || !binding.at("path").is_string() ||
            !binding.contains("sha256") || !binding.at("sha256").is_string() ||
            !binding.contains("max_bytes") || !is_nonnegative_integer(binding.at("max_bytes")))
            continue;
        const auto observed = sha256_repository_evidence_file(evidence_root,
            binding.at("path").get<std::string>(), binding.at("max_bytes").get<std::uint64_t>());
        if (!observed.ok)
            result.reject("/provenance/evidence_bindings/" + std::to_string(index) + "/path",
                "evidence_read", observed.error);
        else if (observed.sha256 != binding.at("sha256").get<std::string>())
            result.reject("/provenance/evidence_bindings/" + std::to_string(index) + "/sha256",
                "evidence_hash_mismatch", "evidence file hash differs from the receipt binding");
    }
    return result;
}
}
