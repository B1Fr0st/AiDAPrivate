#include "decompiler_quality_schema.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cmath>
#include <initializer_list>
#include <map>
#include <set>
#include <sstream>
#include <string_view>
#include <utility>

namespace aida::analysis::c03
{
namespace
{
constexpr std::array<std::string_view, 10> kQualityMetrics{
    "typed_entities", "calls", "fields", "locals", "parameters", "cfg",
    "control_structures", "exception_regions", "type_correctness", "source_coordinates"};

constexpr std::array<std::string_view, 7> kReadabilityMetrics{
    "declaration_count", "naming_consistency_ratio", "max_expression_depth",
    "max_control_nesting", "dead_placeholder_count", "cast_count", "fabricated_body_count"};

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
    if (!value.is_number())
        return false;
    const double number = value.get<double>();
    return std::isfinite(number) && number >= 0.0;
}

bool is_ratio(const json& value)
{
    if (!is_nonnegative_number(value))
        return false;
    return value.get<double>() <= 1.0;
}

bool has_exact_quality_thresholds(const json& value)
{
    const json& expected = decompiler_quality_thresholds();
    if (!value.is_object() || value.size() != expected.size())
        return false;
    for (auto it = expected.begin(); it != expected.end(); ++it) {
        const auto actual = value.find(it.key());
        if (actual == value.end() || *actual != *it)
            return false;
    }
    return true;
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
    std::set<std::string, std::less<>> allowed_names;
    for (const std::string_view name : allowed)
        allowed_names.emplace(name);
    for (auto it = object.begin(); it != object.end(); ++it) {
        if (allowed_names.find(it.key()) == allowed_names.end())
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

bool require_boolean(contract_validation_result_t& result, const json& object,
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

std::set<std::string, std::less<>> string_set(contract_validation_result_t& result,
    const json& value, std::string_view path, bool nonempty)
{
    std::set<std::string, std::less<>> values;
    if (!value.is_array()) {
        result.reject(std::string(path), "array_required", "expected an array");
        return values;
    }
    if (nonempty && value.empty())
        result.reject(std::string(path), "min_items", "array must not be empty");
    for (std::size_t index = 0; index < value.size(); ++index) {
        const json& item = value[index];
        if (!is_nonempty_string(item)) {
            result.reject(std::string(path) + "/" + std::to_string(index), "string_required",
                "expected a non-empty string");
            continue;
        }
        if (!values.insert(item.get<std::string>()).second)
            result.reject(std::string(path) + "/" + std::to_string(index), "duplicate", "duplicate value");
    }
    return values;
}

void require_set_contains(contract_validation_result_t& result,
    const std::set<std::string, std::less<>>& expected,
    const std::set<std::string, std::less<>>& observed, std::string_view path)
{
    for (const auto& value : expected) {
        if (observed.find(value) == observed.end())
            result.reject(std::string(path), "coverage_missing", "missing required value: " + value);
    }
}

void validate_resource_limits(contract_validation_result_t& result, const json& value,
    std::string_view path)
{
    require_closed_object(result, value, path,
        {"max_input_bytes", "max_private_bytes", "max_mapped_bytes", "max_wall_ms"});
    for (const std::string_view field : {"max_input_bytes", "max_private_bytes", "max_mapped_bytes", "max_wall_ms"}) {
        const json* metric = require_field(result, value, path, field);
        if (metric && (!is_nonnegative_integer(*metric) || metric->get<std::uint64_t>() == 0))
            result.reject(std::string(path) + "/" + std::string(field), "positive_integer_required",
                "expected a positive integer");
    }
}

void validate_semantic_facts(contract_validation_result_t& result, const json& value,
    std::string_view path)
{
    require_closed_object(result, value, path,
        {"entity_kinds", "edge_kinds", "metadata_kinds", "identity_kind", "facts_revision"});
    for (const std::string_view field : {"entity_kinds", "edge_kinds", "metadata_kinds"}) {
        const json* items = require_field(result, value, path, field);
        if (items)
            string_set(result, *items, std::string(path) + "/" + std::string(field), true);
    }
    require_string(result, value, path, "identity_kind");
    const json* revision = require_field(result, value, path, "facts_revision");
    if (revision && (!is_nonnegative_integer(*revision) || revision->get<std::uint64_t>() == 0))
        result.reject(std::string(path) + "/facts_revision", "positive_integer_required",
            "expected a positive integer");
}

void validate_confidence_scoring(contract_validation_result_t& result, const json& value,
    std::string_view path, const std::set<std::string, std::less<>>& metric_provenance)
{
    const json* confidence = require_field(result, value, path, "confidence");
    if (!confidence)
        return;
    const std::string confidence_path = std::string(path) + "/confidence";
    require_closed_object(result, *confidence, confidence_path,
        {"observation_count", "known_observations", "explicit_unknown_observations",
         "implicit_unknown_observations", "confidence_sum", "mean_confidence", "minimum_confidence",
         "explicit_unknown_ratio", "explicit_unknown_ids", "provenance_ids"});
    std::array<std::uint64_t, 4> counts{};
    const std::array<std::string_view, 4> count_names{
        "observation_count", "known_observations", "explicit_unknown_observations", "implicit_unknown_observations"};
    for (std::size_t index = 0; index < count_names.size(); ++index) {
        const json* count = require_field(result, *confidence, confidence_path, count_names[index]);
        if (!count || !is_nonnegative_integer(*count)) {
            if (count)
                result.reject(confidence_path + "/" + std::string(count_names[index]),
                    "nonnegative_integer_required", "expected a non-negative integer");
            continue;
        }
        counts[index] = count->get<std::uint64_t>();
    }
    if (counts[1] == 0)
        result.reject(confidence_path + "/known_observations", "known_observation_required",
            "confidence scoring requires at least one known observation");
    if (counts[0] != counts[1] + counts[2] + counts[3])
        result.reject(confidence_path + "/observation_count", "confidence_count_mismatch",
            "observation count disagrees with known and unknown counts");
    if (counts[3] != 0)
        result.reject(confidence_path + "/implicit_unknown_observations", "implicit_unknown_forbidden",
            "unknown observations must be explicitly represented");
    const json* explicit_unknown_ids = require_field(result, *confidence, confidence_path, "explicit_unknown_ids");
    if (explicit_unknown_ids) {
        const auto unknown_ids = string_set(result, *explicit_unknown_ids,
            confidence_path + "/explicit_unknown_ids", false);
        if (unknown_ids.size() != counts[2])
            result.reject(confidence_path + "/explicit_unknown_ids", "explicit_unknown_count_mismatch",
                "explicit unknown identifiers do not match the reported unknown observation count");
    }

    const json* confidence_sum = require_field(result, *confidence, confidence_path, "confidence_sum");
    const json* mean_confidence = require_field(result, *confidence, confidence_path, "mean_confidence");
    const json* minimum_confidence = require_field(result, *confidence, confidence_path, "minimum_confidence");
    const json* explicit_unknown_ratio = require_field(result, *confidence, confidence_path, "explicit_unknown_ratio");
    if (confidence_sum && !is_nonnegative_number(*confidence_sum))
        result.reject(confidence_path + "/confidence_sum", "nonnegative_number_required",
            "expected a finite non-negative number");
    for (const auto& field : std::array<std::pair<std::string_view, const json*>, 3>{
             std::pair<std::string_view, const json*>{"mean_confidence", mean_confidence},
             {"minimum_confidence", minimum_confidence}, {"explicit_unknown_ratio", explicit_unknown_ratio}}) {
        if (field.second && !is_ratio(*field.second))
            result.reject(confidence_path + "/" + std::string(field.first), "ratio_required",
                "expected a finite ratio");
    }
    constexpr double tolerance = 1e-9;
    if (confidence_sum && mean_confidence && is_nonnegative_number(*confidence_sum) && is_ratio(*mean_confidence) &&
        counts[1] != 0 && std::fabs(mean_confidence->get<double>() -
            confidence_sum->get<double>() / static_cast<double>(counts[1])) > tolerance)
        result.reject(confidence_path + "/mean_confidence", "formula_mismatch",
            "mean confidence disagrees with the known-observation confidence sum");
    if (explicit_unknown_ratio && is_ratio(*explicit_unknown_ratio) && counts[0] != 0 &&
        std::fabs(explicit_unknown_ratio->get<double>() -
            static_cast<double>(counts[2]) / static_cast<double>(counts[0])) > tolerance)
        result.reject(confidence_path + "/explicit_unknown_ratio", "formula_mismatch",
            "explicit unknown ratio disagrees with observation counts");
    const json& thresholds = decompiler_quality_thresholds().at("confidence");
    if (mean_confidence && is_ratio(*mean_confidence) &&
        mean_confidence->get<double>() < thresholds.at("mean_confidence_min").get<double>())
        result.reject(confidence_path + "/mean_confidence", "confidence_threshold_not_met",
            "mean confidence is below the versioned scorer threshold");
    if (minimum_confidence && is_ratio(*minimum_confidence) &&
        minimum_confidence->get<double>() < thresholds.at("minimum_confidence_min").get<double>())
        result.reject(confidence_path + "/minimum_confidence", "confidence_threshold_not_met",
            "minimum confidence is below the versioned scorer threshold");
    if (explicit_unknown_ratio && is_ratio(*explicit_unknown_ratio) &&
        explicit_unknown_ratio->get<double>() > thresholds.at("explicit_unknown_ratio_max").get<double>())
        result.reject(confidence_path + "/explicit_unknown_ratio", "explicit_unknown_threshold_exceeded",
            "explicit unknown ratio exceeds the versioned scorer threshold");
    const json* provenance = require_field(result, *confidence, confidence_path, "provenance_ids");
    if (provenance) {
        const auto confidence_provenance = string_set(result, *provenance, confidence_path + "/provenance_ids", true);
        require_set_contains(result, metric_provenance, confidence_provenance, confidence_path + "/provenance_ids");
        require_set_contains(result, confidence_provenance, metric_provenance, confidence_path + "/provenance_ids");
    }
}

void validate_prf_metric(contract_validation_result_t& result, const json& value,
    std::string_view path, std::string_view metric_name)
{
    require_closed_object(result, value, path,
        {"tp", "fp", "fn", "precision", "recall", "f1", "provenance_ids", "confidence"});
    std::array<std::uint64_t, 3> counts{};
    const std::array<std::string_view, 3> count_names{"tp", "fp", "fn"};
    for (std::size_t index = 0; index < count_names.size(); ++index) {
        const json* count = require_field(result, value, path, count_names[index]);
        if (!count || !is_nonnegative_integer(*count)) {
            if (count)
                result.reject(std::string(path) + "/" + std::string(count_names[index]),
                    "nonnegative_integer_required", "expected a non-negative integer");
            continue;
        }
        counts[index] = count->get<std::uint64_t>();
    }
    const json* precision = require_field(result, value, path, "precision");
    const json* recall = require_field(result, value, path, "recall");
    const json* f1 = require_field(result, value, path, "f1");
    if (precision && !is_ratio(*precision))
        result.reject(std::string(path) + "/precision", "ratio_required", "expected a finite ratio");
    if (recall && !is_ratio(*recall))
        result.reject(std::string(path) + "/recall", "ratio_required", "expected a finite ratio");
    if (f1 && !is_ratio(*f1))
        result.reject(std::string(path) + "/f1", "ratio_required", "expected a finite ratio");
    if (precision && recall && f1 && is_ratio(*precision) && is_ratio(*recall) && is_ratio(*f1)) {
        const double expected_precision = counts[0] + counts[1] == 0 ? 0.0 :
            static_cast<double>(counts[0]) / static_cast<double>(counts[0] + counts[1]);
        const double expected_recall = counts[0] + counts[2] == 0 ? 0.0 :
            static_cast<double>(counts[0]) / static_cast<double>(counts[0] + counts[2]);
        const double expected_f1 = expected_precision + expected_recall == 0.0 ? 0.0 :
            2.0 * expected_precision * expected_recall / (expected_precision + expected_recall);
        constexpr double tolerance = 1e-9;
        if (std::fabs(precision->get<double>() - expected_precision) > tolerance)
            result.reject(std::string(path) + "/precision", "formula_mismatch", "precision disagrees with raw counts");
        if (std::fabs(recall->get<double>() - expected_recall) > tolerance)
            result.reject(std::string(path) + "/recall", "formula_mismatch", "recall disagrees with raw counts");
        if (std::fabs(f1->get<double>() - expected_f1) > tolerance)
            result.reject(std::string(path) + "/f1", "formula_mismatch", "F1 disagrees with raw counts");
    }
    const json* provenance = require_field(result, value, path, "provenance_ids");
    std::set<std::string, std::less<>> metric_provenance;
    if (provenance)
        metric_provenance = string_set(result, *provenance, std::string(path) + "/provenance_ids", true);
    validate_confidence_scoring(result, value, path, metric_provenance);
    if (f1 && is_ratio(*f1)) {
        const auto& thresholds = decompiler_quality_thresholds().at("metric_f1_min");
        const auto threshold = thresholds.find(std::string(metric_name));
        if (threshold != thresholds.end() && f1->get<double>() < threshold->get<double>())
            result.reject(std::string(path) + "/f1", "quality_threshold_not_met",
                "F1 is below the versioned scorer threshold");
    }
}

void validate_fixture_record(contract_validation_result_t& result, const json& fixture,
    std::string_view path, const std::set<std::string, std::less<>>& allowed_spdx,
    std::set<std::string, std::less<>>& identifiers,
    std::set<std::string, std::less<>>& formats,
    std::set<std::string, std::less<>>& architectures,
    std::set<std::string, std::less<>>& evidence_domains)
{
    require_closed_object(result, fixture, path,
        {"id", "source", "license", "artifact_binding", "format", "container_chain", "architecture", "mode", "endian",
         "semantic_facts", "resource_limits", "evidence_domains"});
    if (require_string(result, fixture, path, "id")) {
        const auto id = fixture.at("id").get<std::string>();
        if (!identifiers.insert(id).second)
            result.reject(std::string(path) + "/id", "duplicate_fixture", "fixture identifier is duplicated");
    }
    const json* source = require_field(result, fixture, path, "source");
    if (source) {
        require_closed_object(result, *source, std::string(path) + "/source",
            {"kind", "locator", "sha256"});
        require_string(result, *source, std::string(path) + "/source", "kind");
        require_string(result, *source, std::string(path) + "/source", "locator");
        require_sha256(result, *source, std::string(path) + "/source", "sha256");
    }
    const json* license = require_field(result, fixture, path, "license");
    if (license) {
        require_closed_object(result, *license, std::string(path) + "/license", {"spdx", "redistribution"});
        if (require_string(result, *license, std::string(path) + "/license", "spdx") &&
            allowed_spdx.find(license->at("spdx").get<std::string>()) == allowed_spdx.end())
            result.reject(std::string(path) + "/license/spdx", "license_not_allowed",
                "license is not in the manifest allow-list");
        require_boolean(result, *license, std::string(path) + "/license", "redistribution", true);
    }
    const json* binding = require_field(result, fixture, path, "artifact_binding");
    if (binding) {
        require_closed_object(result, *binding, std::string(path) + "/artifact_binding",
            {"status", "algorithm", "content_hash_required"});
        if (require_string(result, *binding, std::string(path) + "/artifact_binding", "status") &&
            binding->at("status").get<std::string>() != "materialization_required")
            result.reject(std::string(path) + "/artifact_binding/status", "binding_status",
                "only materialization_required is allowed in a source manifest");
        if (require_string(result, *binding, std::string(path) + "/artifact_binding", "algorithm") &&
            binding->at("algorithm").get<std::string>() != "sha256")
            result.reject(std::string(path) + "/artifact_binding/algorithm", "hash_algorithm",
                "SHA-256 is required");
        require_boolean(result, *binding, std::string(path) + "/artifact_binding", "content_hash_required", true);
    }
    require_string(result, fixture, path, "format");
    const json* container_chain = require_field(result, fixture, path, "container_chain");
    if (container_chain)
        string_set(result, *container_chain, std::string(path) + "/container_chain", true);
    for (const std::string_view field : {"architecture", "mode", "endian"})
        require_string(result, fixture, path, field);
    if (fixture.contains("format") && is_nonempty_string(fixture.at("format")))
        formats.insert(fixture.at("format").get<std::string>());
    if (fixture.contains("architecture") && is_nonempty_string(fixture.at("architecture")))
        architectures.insert(fixture.at("architecture").get<std::string>());
    const json* fixture_domains = require_field(result, fixture, path, "evidence_domains");
    if (fixture_domains) {
        const auto observed_domains = string_set(result, *fixture_domains,
            std::string(path) + "/evidence_domains", true);
        evidence_domains.insert(observed_domains.begin(), observed_domains.end());
    }
    const json* semantic_facts = require_field(result, fixture, path, "semantic_facts");
    if (semantic_facts)
        validate_semantic_facts(result, *semantic_facts, std::string(path) + "/semantic_facts");
    const json* resource_limits = require_field(result, fixture, path, "resource_limits");
    if (resource_limits)
        validate_resource_limits(result, *resource_limits, std::string(path) + "/resource_limits");
}

void validate_matrix(contract_validation_result_t& result, const json& matrix,
    std::string_view path, const json& corpus)
{
    require_closed_object(result, matrix, path,
        {"required_formats", "observed_formats", "required_architectures", "observed_architectures", "fixture_matrix"});
    const json* required_formats = require_field(result, matrix, path, "required_formats");
    const json* observed_formats = require_field(result, matrix, path, "observed_formats");
    const json* required_architectures = require_field(result, matrix, path, "required_architectures");
    const json* observed_architectures = require_field(result, matrix, path, "observed_architectures");
    if (required_formats && observed_formats)
        require_set_contains(result, string_set(result, *required_formats, std::string(path) + "/required_formats", true),
            string_set(result, *observed_formats, std::string(path) + "/observed_formats", true),
            std::string(path) + "/observed_formats");
    if (required_architectures && observed_architectures)
        require_set_contains(result, string_set(result, *required_architectures,
                std::string(path) + "/required_architectures", true),
            string_set(result, *observed_architectures, std::string(path) + "/observed_architectures", true),
            std::string(path) + "/observed_architectures");
    const json* fixture_matrix = require_field(result, matrix, path, "fixture_matrix");
    if (!fixture_matrix || !fixture_matrix->is_array()) {
        if (fixture_matrix)
            result.reject(std::string(path) + "/fixture_matrix", "array_required", "expected an array");
        return;
    }
    if (fixture_matrix->empty())
        result.reject(std::string(path) + "/fixture_matrix", "min_items", "matrix must contain fixture rows");
    std::set<std::string, std::less<>> corpus_ids;
    if (corpus.is_object() && corpus.contains("fixtures") && corpus.at("fixtures").is_array()) {
        for (const auto& fixture : corpus.at("fixtures")) {
            if (fixture.is_object() && fixture.contains("id") && is_nonempty_string(fixture.at("id")))
                corpus_ids.insert(fixture.at("id").get<std::string>());
        }
    }
    std::set<std::string, std::less<>> row_ids;
    for (std::size_t index = 0; index < fixture_matrix->size(); ++index) {
        const auto& row = (*fixture_matrix)[index];
        const std::string row_path = std::string(path) + "/fixture_matrix/" + std::to_string(index);
        require_closed_object(result, row, row_path, {"fixture_id", "format", "architecture", "mode", "endian"});
        if (require_string(result, row, row_path, "fixture_id")) {
            const auto id = row.at("fixture_id").get<std::string>();
            if (corpus_ids.find(id) == corpus_ids.end())
                result.reject(row_path + "/fixture_id", "unknown_fixture", "fixture is absent from corpus evidence");
            if (!row_ids.insert(id).second)
                result.reject(row_path + "/fixture_id", "duplicate_fixture", "fixture matrix has duplicate row");
        }
        for (const std::string_view field : {"format", "architecture", "mode", "endian"})
            require_string(result, row, row_path, field);
    }
    for (const auto& id : corpus_ids) {
        if (row_ids.find(id) == row_ids.end())
            result.reject(std::string(path) + "/fixture_matrix", "coverage_missing",
                "corpus fixture is absent from matrix: " + id);
    }
}
}

void contract_validation_result_t::reject(std::string path, std::string code, std::string message)
{
    valid = false;
    violations.push_back({std::move(path), std::move(code), std::move(message)});
}

std::string contract_validation_result_t::summary() const
{
    if (valid)
        return "valid";
    std::ostringstream stream;
    stream << violations.size() << " contract violation" << (violations.size() == 1 ? "" : "s");
    if (!violations.empty())
        stream << ": " << violations.front().code << " at " << violations.front().path;
    return stream.str();
}

json contract_validation_result_t::to_json() const
{
    json errors = json::array();
    for (const auto& violation : violations)
        errors.push_back({{"path", violation.path}, {"code", violation.code}, {"message", violation.message}});
    return {{"valid", valid}, {"summary", summary()}, {"violations", std::move(errors)}};
}

const json& corpus_manifest_schema()
{
    static const json schema = json::parse(R"schema({
        "$schema":"https://json-schema.org/draft-07/schema#",
        "$id":"aida.c03.corpus-manifest.v2",
        "type":"object",
        "required":["schema","schema_version","corpus_id","license_policy","generator_source","required_coverage","fixtures","malformed_case_manifest"],
        "additionalProperties":false,
        "properties":{
            "schema":{"const":"aida.c03.corpus-manifest"},
            "schema_version":{"const":2},
            "corpus_id":{"type":"string","minLength":1},
            "license_policy":{"type":"object"},
            "generator_source":{"type":"object"},
            "required_coverage":{"type":"object"},
            "fixtures":{"type":"array","minItems":1},
            "malformed_case_manifest":{"type":"object"}
        }
    })schema");
    return schema;
}

const json& decompiler_quality_thresholds()
{
    static const json thresholds = {
        {"threshold_schema", "aida.c03.decompiler-quality-thresholds"},
        {"threshold_schema_version", 1},
        {"scorer_revision", 1},
        {"metric_f1_min", {
            {"typed_entities", 0.70}, {"calls", 0.70}, {"fields", 0.70}, {"locals", 0.65},
            {"parameters", 0.75}, {"cfg", 0.80}, {"control_structures", 0.70},
            {"exception_regions", 0.65}, {"type_correctness", 0.70}, {"source_coordinates", 0.80}}},
        {"confidence", {
            {"mean_confidence_min", 0.60}, {"minimum_confidence_min", 0.10},
            {"explicit_unknown_ratio_max", 0.25}}},
        {"baseline_delta_min", {
            {"typed_entities", 0.0}, {"calls", 0.0}, {"fields", 0.0}, {"locals", 0.0},
            {"parameters", 0.0}, {"cfg", 0.0}, {"control_structures", 0.0},
            {"exception_regions", 0.0}, {"type_correctness", 0.0}, {"source_coordinates", 0.0}}}
    };
    return thresholds;
}

const json& decompiler_quality_receipt_schema()
{
    static const json schema = json::parse(R"schema({
        "$schema":"https://json-schema.org/draft-07/schema#",
        "$id":"aida.c03.decompiler-quality-receipt.v2",
        "type":"object",
        "required":["schema","schema_version","receipt_id","provenance","corpus","matrix","execution","metrics","readability","determinism","baseline","thresholds","diagnostics","failures","claims","receipt_sha256"],
        "additionalProperties":false,
        "properties":{
            "schema":{"const":"aida.c03.decompiler-quality-receipt"},
            "schema_version":{"const":2},
            "receipt_id":{"type":"string","minLength":1},
            "provenance":{"type":"object"},
            "corpus":{"type":"object"},
            "matrix":{"type":"object"},
            "execution":{"type":"object"},
            "metrics":{"type":"object"},
            "readability":{"type":"object"},
            "determinism":{"type":"object"},
            "baseline":{"type":"object"},
            "thresholds":{"type":"object"},
            "diagnostics":{"type":"object"},
            "failures":{"type":"array"},
            "claims":{"type":"array","minItems":1},
            "receipt_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}
        }
    })schema");
    return schema;
}

contract_validation_result_t validate_corpus_manifest(const json& manifest)
{
    contract_validation_result_t result;
    require_closed_object(result, manifest, "",
        {"schema", "schema_version", "corpus_id", "license_policy", "generator_source", "required_coverage",
         "fixtures", "malformed_case_manifest"});
    if (require_string(result, manifest, "", "schema") && manifest.at("schema") != "aida.c03.corpus-manifest")
        result.reject("/schema", "schema_id", "unexpected manifest schema identifier");
    const json* version = require_field(result, manifest, "", "schema_version");
    if (version && (!version->is_number_integer() || version->get<std::int64_t>() != 2))
        result.reject("/schema_version", "schema_version", "expected schema version 2");
    require_string(result, manifest, "", "corpus_id");

    std::set<std::string, std::less<>> allowed_spdx;
    const json* policy = require_field(result, manifest, "", "license_policy");
    if (policy) {
        require_closed_object(result, *policy, "/license_policy", {"allowed_spdx", "redistribution_required"});
        const json* allowed = require_field(result, *policy, "/license_policy", "allowed_spdx");
        if (allowed)
            allowed_spdx = string_set(result, *allowed, "/license_policy/allowed_spdx", true);
        require_boolean(result, *policy, "/license_policy", "redistribution_required", true);
    }

    const json* generator_source = require_field(result, manifest, "", "generator_source");
    if (generator_source) {
        require_closed_object(result, *generator_source, "/generator_source", {"path", "sha256", "license"});
        require_string(result, *generator_source, "/generator_source", "path");
        require_sha256(result, *generator_source, "/generator_source", "sha256");
        if (require_string(result, *generator_source, "/generator_source", "license") &&
            !allowed_spdx.empty() && allowed_spdx.find(generator_source->at("license").get<std::string>()) == allowed_spdx.end())
            result.reject("/generator_source/license", "license_not_allowed", "generator license is not allowed");
    }

    std::set<std::string, std::less<>> required_formats;
    std::set<std::string, std::less<>> required_architectures;
    std::set<std::string, std::less<>> required_domains;
    const json* coverage = require_field(result, manifest, "", "required_coverage");
    if (coverage) {
        require_closed_object(result, *coverage, "/required_coverage", {"formats", "architectures", "evidence_domains"});
        const json* formats = require_field(result, *coverage, "/required_coverage", "formats");
        const json* architectures = require_field(result, *coverage, "/required_coverage", "architectures");
        const json* domains = require_field(result, *coverage, "/required_coverage", "evidence_domains");
        if (formats)
            required_formats = string_set(result, *formats, "/required_coverage/formats", true);
        if (architectures)
            required_architectures = string_set(result, *architectures, "/required_coverage/architectures", true);
        if (domains)
            required_domains = string_set(result, *domains, "/required_coverage/evidence_domains", true);
    }
    const std::set<std::string, std::less<>> mandatory_evidence_domains{
        "static_analysis", "overlay_projection", "compatibility_contract"};
    require_set_contains(result, mandatory_evidence_domains, required_domains,
        "/required_coverage/evidence_domains");

    std::set<std::string, std::less<>> identifiers;
    std::set<std::string, std::less<>> formats;
    std::set<std::string, std::less<>> architectures;
    std::set<std::string, std::less<>> evidence_domains;
    const json* fixtures = require_field(result, manifest, "", "fixtures");
    if (!fixtures || !fixtures->is_array()) {
        if (fixtures)
            result.reject("/fixtures", "array_required", "expected an array");
    } else {
        if (fixtures->empty())
            result.reject("/fixtures", "min_items", "manifest must declare fixtures");
        for (std::size_t index = 0; index < fixtures->size(); ++index)
            validate_fixture_record(result, (*fixtures)[index], "/fixtures/" + std::to_string(index),
                allowed_spdx, identifiers, formats, architectures, evidence_domains);
    }
    require_set_contains(result, required_formats, formats, "/fixtures");
    require_set_contains(result, required_architectures, architectures, "/fixtures");
    require_set_contains(result, required_domains, evidence_domains, "/fixtures");

    const json* malformed_manifest = require_field(result, manifest, "", "malformed_case_manifest");
    if (malformed_manifest) {
        require_closed_object(result, *malformed_manifest, "/malformed_case_manifest", {"path", "sha256"});
        require_string(result, *malformed_manifest, "/malformed_case_manifest", "path");
        require_sha256(result, *malformed_manifest, "/malformed_case_manifest", "sha256");
    }
    return result;
}

contract_validation_result_t validate_malformed_case_manifest(const json& manifest,
    const json& malformed_cases)
{
    contract_validation_result_t result;
    std::set<std::string, std::less<>> fixture_ids;
    if (manifest.is_object() && manifest.contains("fixtures") && manifest.at("fixtures").is_array()) {
        for (const auto& fixture : manifest.at("fixtures")) {
            if (fixture.is_object() && fixture.contains("id") && is_nonempty_string(fixture.at("id")))
                fixture_ids.insert(fixture.at("id").get<std::string>());
        }
    }
    require_closed_object(result, malformed_cases, "",
        {"schema", "schema_version", "source", "license", "cases"});
    if (require_string(result, malformed_cases, "", "schema") &&
        malformed_cases.at("schema") != "aida.c03.malformed-cases")
        result.reject("/schema", "schema_id", "unexpected malformed-case schema identifier");
    const json* version = require_field(result, malformed_cases, "", "schema_version");
    if (version && (!version->is_number_integer() || version->get<std::int64_t>() != 1))
        result.reject("/schema_version", "schema_version", "expected schema version 1");
    const json* source = require_field(result, malformed_cases, "", "source");
    if (source) {
        require_closed_object(result, *source, "/source", {"path", "sha256"});
        require_string(result, *source, "/source", "path");
        require_sha256(result, *source, "/source", "sha256");
    }
    const json* license = require_field(result, malformed_cases, "", "license");
    if (license) {
        require_closed_object(result, *license, "/license", {"spdx", "redistribution"});
        require_string(result, *license, "/license", "spdx");
        require_boolean(result, *license, "/license", "redistribution", true);
    }
    const json* cases = require_field(result, malformed_cases, "", "cases");
    if (!cases || !cases->is_array()) {
        if (cases)
            result.reject("/cases", "array_required", "expected an array");
        return result;
    }
    if (cases->empty())
        result.reject("/cases", "min_items", "malformed cases are required");
    const std::set<std::string, std::less<>> supported_kinds{
        "truncated", "zip_bomb", "integer_overflow", "invalid_signature", "invalid_offset", "invalid_length"};
    std::set<std::string, std::less<>> identifiers;
    for (std::size_t index = 0; index < cases->size(); ++index) {
        const auto& item = (*cases)[index];
        const std::string path = "/cases/" + std::to_string(index);
        require_closed_object(result, item, path,
            {"id", "source_fixture_id", "kind", "mutation", "expected_error_codes", "max_wall_ms", "max_private_bytes"});
        if (require_string(result, item, path, "id") && !identifiers.insert(item.at("id").get<std::string>()).second)
            result.reject(path + "/id", "duplicate", "malformed case identifier is duplicated");
        if (require_string(result, item, path, "source_fixture_id") &&
            fixture_ids.find(item.at("source_fixture_id").get<std::string>()) == fixture_ids.end())
            result.reject(path + "/source_fixture_id", "unknown_fixture", "source fixture is absent from corpus manifest");
        if (require_string(result, item, path, "kind") && supported_kinds.find(item.at("kind").get<std::string>()) == supported_kinds.end())
            result.reject(path + "/kind", "unsupported_malformed_kind", "unsupported malformed class");
        require_string(result, item, path, "mutation");
        const json* codes = require_field(result, item, path, "expected_error_codes");
        if (codes)
            string_set(result, *codes, path + "/expected_error_codes", true);
        for (const std::string_view field : {"max_wall_ms", "max_private_bytes"}) {
            const json* limit = require_field(result, item, path, field);
            if (limit && (!is_nonnegative_integer(*limit) || limit->get<std::uint64_t>() == 0))
                result.reject(path + "/" + std::string(field), "positive_integer_required",
                    "expected a positive integer");
        }
    }
    return result;
}

contract_validation_result_t validate_decompiler_quality_receipt(const json& receipt)
{
    contract_validation_result_t result;
    require_closed_object(result, receipt, "",
        {"schema", "schema_version", "receipt_id", "provenance", "corpus", "matrix", "execution",
         "metrics", "readability", "determinism", "baseline", "thresholds", "diagnostics", "failures", "claims", "receipt_sha256"});
    if (require_string(result, receipt, "", "schema") &&
        receipt.at("schema") != "aida.c03.decompiler-quality-receipt")
        result.reject("/schema", "schema_id", "unexpected decompiler quality schema identifier");
    const json* version = require_field(result, receipt, "", "schema_version");
    if (version && (!version->is_number_integer() || version->get<std::int64_t>() != 2))
        result.reject("/schema_version", "schema_version", "expected schema version 2");
    require_string(result, receipt, "", "receipt_id");
    require_sha256(result, receipt, "", "receipt_sha256");

    const json* provenance = require_field(result, receipt, "", "provenance");
    std::set<std::string, std::less<>> providers;
    std::map<std::string, std::string, std::less<>> provider_build_hashes;
    if (provenance) {
        require_closed_object(result, *provenance, "/provenance",
            {"authorization_id", "harness_build_sha256", "scorer_build_sha256", "provider_builds"});
        require_string(result, *provenance, "/provenance", "authorization_id");
        require_sha256(result, *provenance, "/provenance", "harness_build_sha256");
        require_sha256(result, *provenance, "/provenance", "scorer_build_sha256");
        const json* provider_builds = require_field(result, *provenance, "/provenance", "provider_builds");
        if (provider_builds && provider_builds->is_array()) {
            if (provider_builds->empty())
                result.reject("/provenance/provider_builds", "min_items", "provider build evidence is required");
            for (std::size_t index = 0; index < provider_builds->size(); ++index) {
                const auto& provider = (*provider_builds)[index];
                const std::string path = "/provenance/provider_builds/" + std::to_string(index);
                require_closed_object(result, provider, path, {"provider", "build_sha256", "worker_manifest_sha256"});
                if (require_string(result, provider, path, "provider") &&
                    !providers.insert(provider.at("provider").get<std::string>()).second)
                    result.reject(path + "/provider", "duplicate_provider", "provider build evidence is duplicated");
                if (require_sha256(result, provider, path, "build_sha256") &&
                    provider.contains("provider") && is_nonempty_string(provider.at("provider")))
                    provider_build_hashes.emplace(provider.at("provider").get<std::string>(),
                        provider.at("build_sha256").get<std::string>());
                require_sha256(result, provider, path, "worker_manifest_sha256");
            }
            for (const std::string_view baseline_provider : {"ghidra_printc", "aida_current"}) {
                if (providers.find(std::string(baseline_provider)) == providers.end())
                    result.reject("/provenance/provider_builds", "baseline_provider_missing",
                        "required baseline provider lacks build provenance");
            }
        } else if (provider_builds) {
            result.reject("/provenance/provider_builds", "array_required", "expected an array");
        }
    }

    const json* corpus = require_field(result, receipt, "", "corpus");
    std::string corpus_fixture_set_sha256;
    if (corpus) {
        require_closed_object(result, *corpus, "/corpus", {"manifest_sha256", "fixture_set_sha256", "fixtures"});
        require_sha256(result, *corpus, "/corpus", "manifest_sha256");
        if (require_sha256(result, *corpus, "/corpus", "fixture_set_sha256"))
            corpus_fixture_set_sha256 = corpus->at("fixture_set_sha256").get<std::string>();
        const json* fixtures = require_field(result, *corpus, "/corpus", "fixtures");
        if (fixtures && fixtures->is_array()) {
            if (fixtures->empty())
                result.reject("/corpus/fixtures", "min_items", "scored fixture evidence is required");
            std::set<std::string, std::less<>> fixture_ids;
            for (std::size_t index = 0; index < fixtures->size(); ++index) {
                const auto& fixture = (*fixtures)[index];
                const std::string path = "/corpus/fixtures/" + std::to_string(index);
                require_closed_object(result, fixture, path,
                    {"id", "artifact_sha256", "source_provenance_sha256", "semantic_facts_sha256", "format", "architecture", "mode", "endian"});
                if (require_string(result, fixture, path, "id") &&
                    !fixture_ids.insert(fixture.at("id").get<std::string>()).second)
                    result.reject(path + "/id", "duplicate_fixture", "fixture evidence is duplicated");
                for (const std::string_view field : {"artifact_sha256", "source_provenance_sha256", "semantic_facts_sha256"})
                    require_sha256(result, fixture, path, field);
                for (const std::string_view field : {"format", "architecture", "mode", "endian"})
                    require_string(result, fixture, path, field);
            }
        } else if (fixtures) {
            result.reject("/corpus/fixtures", "array_required", "expected an array");
        }
    }

    const json* matrix = require_field(result, receipt, "", "matrix");
    if (matrix && corpus)
        validate_matrix(result, *matrix, "/matrix", *corpus);

    const json* execution = require_field(result, receipt, "", "execution");
    if (execution) {
        require_closed_object(result, *execution, "/execution",
            {"run_id", "started_utc", "ended_utc", "schedule", "cache_state", "target_execution_forbidden"});
        for (const std::string_view field : {"run_id", "started_utc", "ended_utc", "schedule", "cache_state"})
            require_string(result, *execution, "/execution", field);
        require_boolean(result, *execution, "/execution", "target_execution_forbidden", true);
    }

    const json* metrics = require_field(result, receipt, "", "metrics");
    if (metrics) {
        std::set<std::string, std::less<>> allowed;
        for (const auto metric : kQualityMetrics)
            allowed.emplace(metric);
        if (!metrics->is_object()) {
            result.reject("/metrics", "object_required", "expected an object");
        } else {
            for (auto it = metrics->begin(); it != metrics->end(); ++it) {
                if (allowed.find(it.key()) == allowed.end())
                    result.reject("/metrics/" + it.key(), "subjective_or_unknown_metric",
                        "only objective versioned metrics are allowed");
            }
            for (const auto name : kQualityMetrics) {
                const json* metric = require_field(result, *metrics, "/metrics", name);
                if (metric)
                    validate_prf_metric(result, *metric, "/metrics/" + std::string(name), name);
            }
        }
    }

    const json* thresholds = require_field(result, receipt, "", "thresholds");
    if (thresholds && !has_exact_quality_thresholds(*thresholds))
        result.reject("/thresholds", "threshold_drift", "receipt thresholds must equal the versioned scorer contract");

    const json* readability = require_field(result, receipt, "", "readability");
    if (readability) {
        std::set<std::string, std::less<>> allowed;
        for (const auto metric : kReadabilityMetrics)
            allowed.emplace(metric);
        if (!readability->is_object()) {
            result.reject("/readability", "object_required", "expected an object");
        } else {
            for (auto it = readability->begin(); it != readability->end(); ++it) {
                if (allowed.find(it.key()) == allowed.end())
                    result.reject("/readability/" + it.key(), "subjective_metric", "subjective readability metric is forbidden");
            }
            for (const auto field : kReadabilityMetrics) {
                const json* value = require_field(result, *readability, "/readability", field);
                if (!value)
                    continue;
                const bool ratio = field == "naming_consistency_ratio";
                if ((ratio && !is_ratio(*value)) || (!ratio && !is_nonnegative_integer(*value)))
                    result.reject("/readability/" + std::string(field), ratio ? "ratio_required" : "nonnegative_integer_required",
                        "invalid objective readability value");
                if (field == "fabricated_body_count" && is_nonnegative_integer(*value) && value->get<std::uint64_t>() != 0)
                    result.reject("/readability/fabricated_body_count", "fabricated_body", "quality receipt contains fabricated body evidence");
            }
        }
    }

    const json* determinism = require_field(result, receipt, "", "determinism");
    if (determinism) {
        require_closed_object(result, *determinism, "/determinism", {"canonicalization_version", "runs"});
        require_string(result, *determinism, "/determinism", "canonicalization_version");
        const json* runs = require_field(result, *determinism, "/determinism", "runs");
        if (runs && runs->is_array()) {
            if (runs->size() < 2)
                result.reject("/determinism/runs", "min_items", "determinism requires at least two runs");
            std::set<std::string, std::less<>> schedule_cache_pairs;
            std::string ast_hash;
            std::string source_map_hash;
            for (std::size_t index = 0; index < runs->size(); ++index) {
                const auto& run = (*runs)[index];
                const std::string path = "/determinism/runs/" + std::to_string(index);
                require_closed_object(result, run, path,
                    {"run_id", "schedule", "cache_state", "normalized_ast_sha256", "source_map_sha256", "outcome"});
                for (const std::string_view field : {"run_id", "schedule", "cache_state", "outcome"})
                    require_string(result, run, path, field);
                require_sha256(result, run, path, "normalized_ast_sha256");
                require_sha256(result, run, path, "source_map_sha256");
                if (run.contains("outcome") && is_nonempty_string(run.at("outcome")) && run.at("outcome").get<std::string>() != "success")
                    result.reject(path + "/outcome", "determinism_incomplete", "determinism proof requires successful runs");
                if (run.contains("schedule") && run.contains("cache_state") && is_nonempty_string(run.at("schedule")) &&
                    is_nonempty_string(run.at("cache_state")))
                    schedule_cache_pairs.insert(run.at("schedule").get<std::string>() + "\n" + run.at("cache_state").get<std::string>());
                if (run.contains("normalized_ast_sha256") && is_sha256(run.at("normalized_ast_sha256"))) {
                    const auto& current = run.at("normalized_ast_sha256").get_ref<const std::string&>();
                    if (ast_hash.empty()) ast_hash = current;
                    else if (ast_hash != current) result.reject(path + "/normalized_ast_sha256", "nondeterministic_ast", "AST hash differs between runs");
                }
                if (run.contains("source_map_sha256") && is_sha256(run.at("source_map_sha256"))) {
                    const auto& current = run.at("source_map_sha256").get_ref<const std::string&>();
                    if (source_map_hash.empty()) source_map_hash = current;
                    else if (source_map_hash != current) result.reject(path + "/source_map_sha256", "nondeterministic_source_map", "source-map hash differs between runs");
                }
            }
            if (runs->size() >= 2 && schedule_cache_pairs.size() < 2)
                result.reject("/determinism/runs", "insufficient_schedule_cache_variation",
                    "determinism requires distinct schedule or cache-state evidence");
        } else if (runs) {
            result.reject("/determinism/runs", "array_required", "expected an array");
        }
    }

    const json* baseline = require_field(result, receipt, "", "baseline");
    if (baseline) {
        require_closed_object(result, *baseline, "/baseline",
            {"ghidra_printc", "aida_current"});
        for (const std::string_view baseline_name : {"ghidra_printc", "aida_current"}) {
            const std::string baseline_path = "/baseline/" + std::string(baseline_name);
            const json* baseline_entry = require_field(result, *baseline, "/baseline", baseline_name);
            if (!baseline_entry)
                continue;
            require_closed_object(result, *baseline_entry, baseline_path,
                {"provider", "provider_build_sha256", "same_fixture_set", "fixture_set_sha256", "metric_deltas"});
            const bool provider_valid = require_string(result, *baseline_entry, baseline_path, "provider");
            if (provider_valid && baseline_entry->at("provider").get<std::string>() != baseline_name)
                result.reject(baseline_path + "/provider", "baseline_provider_identity",
                    "baseline provider does not match its required comparator");
            if (provider_valid && providers.find(baseline_entry->at("provider").get<std::string>()) == providers.end())
                result.reject(baseline_path + "/provider", "baseline_provider_missing",
                    "baseline provider lacks build provenance");
            const bool build_valid = require_sha256(result, *baseline_entry, baseline_path, "provider_build_sha256");
            if (provider_valid && build_valid) {
                const auto known_build = provider_build_hashes.find(baseline_entry->at("provider").get<std::string>());
                if (known_build == provider_build_hashes.end() ||
                    known_build->second != baseline_entry->at("provider_build_sha256").get<std::string>())
                    result.reject(baseline_path + "/provider_build_sha256", "baseline_build_mismatch",
                        "baseline build hash does not match recorded provider provenance");
            }
            require_boolean(result, *baseline_entry, baseline_path, "same_fixture_set", true);
            const bool fixture_set_valid = require_sha256(result, *baseline_entry, baseline_path, "fixture_set_sha256");
            if (fixture_set_valid && !corpus_fixture_set_sha256.empty() &&
                baseline_entry->at("fixture_set_sha256").get<std::string>() != corpus_fixture_set_sha256)
                result.reject(baseline_path + "/fixture_set_sha256", "baseline_fixture_set_mismatch",
                    "baseline does not use the receipt fixture set");
            const json* deltas = require_field(result, *baseline_entry, baseline_path, "metric_deltas");
            if (!deltas || !deltas->is_object()) {
                if (deltas)
                    result.reject(baseline_path + "/metric_deltas", "object_required", "expected an object");
                continue;
            }
            for (const auto name : kQualityMetrics) {
                const std::string metric_name(name);
                const auto delta_it = deltas->find(metric_name);
                if (delta_it == deltas->end()) {
                    result.reject(baseline_path + "/metric_deltas/" + metric_name, "required", "baseline delta is required");
                    continue;
                }
                const std::string path = baseline_path + "/metric_deltas/" + metric_name;
                require_closed_object(result, *delta_it, path, {"baseline_f1", "current_f1", "delta"});
                const json* baseline_f1 = require_field(result, *delta_it, path, "baseline_f1");
                const json* current_f1 = require_field(result, *delta_it, path, "current_f1");
                const json* delta = require_field(result, *delta_it, path, "delta");
                if (baseline_f1 && !is_ratio(*baseline_f1)) result.reject(path + "/baseline_f1", "ratio_required", "expected a finite ratio");
                if (current_f1 && !is_ratio(*current_f1)) result.reject(path + "/current_f1", "ratio_required", "expected a finite ratio");
                if (delta && (!delta->is_number() || !std::isfinite(delta->get<double>())))
                    result.reject(path + "/delta", "finite_number_required", "expected a finite number");
                if (current_f1 && is_ratio(*current_f1) && metrics && metrics->is_object() && metrics->contains(metric_name) &&
                    metrics->at(metric_name).is_object() && metrics->at(metric_name).contains("f1") &&
                    is_ratio(metrics->at(metric_name).at("f1")) &&
                    std::fabs(current_f1->get<double>() - metrics->at(metric_name).at("f1").get<double>()) > 1e-9)
                    result.reject(path + "/current_f1", "metric_mismatch", "baseline comparison disagrees with raw metric");
                if (baseline_f1 && current_f1 && delta && is_ratio(*baseline_f1) && is_ratio(*current_f1) &&
                    delta->is_number() && std::isfinite(delta->get<double>())) {
                    if (std::fabs(delta->get<double>() - (current_f1->get<double>() - baseline_f1->get<double>())) > 1e-9)
                        result.reject(path + "/delta", "formula_mismatch", "delta disagrees with baseline and current values");
                    const double minimum_delta = decompiler_quality_thresholds().at("baseline_delta_min").at(metric_name).get<double>();
                    if (delta->get<double>() < minimum_delta)
                        result.reject(path + "/delta", "baseline_regression",
                            "current scorer regresses below the versioned baseline threshold");
                }
            }
        }
    }

    const json* diagnostics = require_field(result, receipt, "", "diagnostics");
    if (diagnostics) {
        require_closed_object(result, *diagnostics, "/diagnostics", {"summary", "events", "cancellation"});
        const json* summary = require_field(result, *diagnostics, "/diagnostics", "summary");
        if (summary) {
            require_closed_object(result, *summary, "/diagnostics/summary",
                {"provider_crash", "timeout", "unsupported", "cancelled", "success"});
            for (const std::string_view field : {"provider_crash", "timeout", "unsupported", "cancelled", "success"}) {
                const json* count = require_field(result, *summary, "/diagnostics/summary", field);
                if (count && !is_nonnegative_integer(*count))
                    result.reject("/diagnostics/summary/" + std::string(field), "nonnegative_integer_required",
                        "expected a non-negative integer");
            }
        }
        const json* events = require_field(result, *diagnostics, "/diagnostics", "events");
        if (events && !events->is_array())
            result.reject("/diagnostics/events", "array_required", "expected an array");
        const json* cancellation = require_field(result, *diagnostics, "/diagnostics", "cancellation");
        if (cancellation) {
            require_closed_object(result, *cancellation, "/diagnostics/cancellation",
                {"requested", "completed_jobs", "cancelled_jobs", "p95_ms"});
            require_boolean(result, *cancellation, "/diagnostics/cancellation", "requested", true);
            for (const std::string_view field : {"completed_jobs", "cancelled_jobs", "p95_ms"}) {
                const json* value = require_field(result, *cancellation, "/diagnostics/cancellation", field);
                if (value && !is_nonnegative_number(*value))
                    result.reject("/diagnostics/cancellation/" + std::string(field), "nonnegative_number_required",
                        "expected a finite non-negative number");
            }
        }
    }

    const json* failures = require_field(result, receipt, "", "failures");
    if (failures && !failures->is_array())
        result.reject("/failures", "array_required", "expected an array");

    const json* claims = require_field(result, receipt, "", "claims");
    if (claims && claims->is_array()) {
        if (claims->empty())
            result.reject("/claims", "min_items", "quality claims require objective evidence");
        for (std::size_t index = 0; index < claims->size(); ++index) {
            const auto& claim = (*claims)[index];
            const std::string path = "/claims/" + std::to_string(index);
            require_closed_object(result, claim, path,
                {"id", "metric_id", "actual", "threshold", "comparator", "evidence_ids"});
            require_string(result, claim, path, "id");
            const json* metric_id = require_field(result, claim, path, "metric_id");
            const json* actual = require_field(result, claim, path, "actual");
            const json* threshold = require_field(result, claim, path, "threshold");
            if (metric_id && !is_nonempty_string(*metric_id))
                result.reject(path + "/metric_id", "string_required", "expected a non-empty metric identifier");
            if (actual && !is_ratio(*actual)) result.reject(path + "/actual", "ratio_required", "expected a finite ratio");
            if (threshold && !is_ratio(*threshold)) result.reject(path + "/threshold", "ratio_required", "expected a finite ratio");
            const bool gte = require_string(result, claim, path, "comparator") &&
                claim.at("comparator").get<std::string>() == "gte";
            if (!gte && claim.contains("comparator") && is_nonempty_string(claim.at("comparator")))
                result.reject(path + "/comparator", "unsupported_comparator", "only gte quality claims are allowed");
            const json* evidence_ids = require_field(result, claim, path, "evidence_ids");
            if (evidence_ids)
                string_set(result, *evidence_ids, path + "/evidence_ids", true);
            if (threshold && is_ratio(*threshold) && actual && is_ratio(*actual) && gte &&
                actual->get<double>() < threshold->get<double>())
                result.reject(path + "/actual", "threshold_not_met", "gte quality claim does not meet its declared threshold");
            if (metric_id && is_nonempty_string(*metric_id) && metrics && metrics->is_object()) {
                const auto name = metric_id->get<std::string>();
                if (metrics->find(name) == metrics->end())
                    result.reject(path + "/metric_id", "unknown_metric", "claim does not reference an objective metric");
                else if (actual && is_ratio(*actual) && metrics->at(name).is_object() && metrics->at(name).contains("f1") &&
                    is_ratio(metrics->at(name).at("f1")) &&
                    std::fabs(actual->get<double>() - metrics->at(name).at("f1").get<double>()) > 1e-9)
                    result.reject(path + "/actual", "fabricated_claim", "claim value disagrees with raw metric");
                const auto threshold_it = decompiler_quality_thresholds().at("metric_f1_min").find(name);
                if (threshold && is_ratio(*threshold) && threshold_it != decompiler_quality_thresholds().at("metric_f1_min").end() &&
                    threshold->get<double>() < threshold_it->get<double>())
                    result.reject(path + "/threshold", "threshold_weakened",
                        "claim threshold is below the versioned scorer threshold");
            }
        }
    } else if (claims) {
        result.reject("/claims", "array_required", "expected an array");
    }
    return result;
}
}
