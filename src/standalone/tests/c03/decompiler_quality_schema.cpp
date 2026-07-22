#include "decompiler_quality_schema.hpp"
#include "evidence_hash.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cmath>
#include <initializer_list>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string_view>
#include <tuple>
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

constexpr std::size_t kProviderEvidenceStringMaxBytes = 65'536;
constexpr std::size_t kProviderEvidenceStringSetMaxItems = 65'536;
constexpr std::size_t kProviderEvidenceStringSetMaxBytes = 16U * 1024U * 1024U;
constexpr std::size_t kProviderRunDiagnosticMaxItems = 65'536;
constexpr std::size_t kProviderRunDiagnosticMaxBytes = 16U * 1024U * 1024U;
constexpr std::size_t kProviderCancellationDiagnosticMaxItems = 1'024;
constexpr std::size_t kProviderCancellationDiagnosticMaxBytes = 1U * 1024U * 1024U;
constexpr std::uint64_t kProviderArtifactBundleMinimumBytes = 36;
constexpr std::uint64_t kProviderArtifactRawMaxBytes = 24ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kProviderArtifactEncodedMaxBytes = 48ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kProviderStructuredEncodedMaxBytes = 24ULL * 1024ULL * 1024ULL;

std::size_t encoded_string_upper_bound(const std::string_view value)
{
    if (value.size() > ((std::numeric_limits<std::size_t>::max)() - 2U) / 6U)
        return (std::numeric_limits<std::size_t>::max)();
    return value.size() * 6U + 2U;
}

bool charge_encoded_bytes(std::size_t& cumulative, const std::size_t encoded,
                          const std::size_t maximum)
{
    if (cumulative > maximum || encoded > maximum - cumulative)
        return false;
    cumulative += encoded;
    return true;
}

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
    std::string_view path, std::string_view name,
    const std::size_t maximum_bytes = kProviderEvidenceStringMaxBytes)
{
    const json* value = require_field(result, object, path, name);
    if (!value)
        return false;
    if (!is_nonempty_string(*value)) {
        result.reject(std::string(path) + "/" + std::string(name), "string_required",
            "expected a non-empty string");
        return false;
    }
    if (value->get_ref<const std::string&>().size() > maximum_bytes) {
        result.reject(std::string(path) + "/" + std::string(name), "string_too_long",
            "string exceeds its evidence bound");
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
    if (value.size() > kProviderEvidenceStringSetMaxItems) {
        result.reject(std::string(path), "max_items",
            "string set exceeds the 65536-item evidence bound");
        return values;
    }
    std::size_t cumulative_bytes = 0;
    for (std::size_t index = 0; index < value.size(); ++index) {
        const json& item = value[index];
        if (!is_nonempty_string(item)) {
            result.reject(std::string(path) + "/" + std::to_string(index), "string_required",
                "expected a non-empty string");
            continue;
        }
        const auto& text = item.get_ref<const std::string&>();
        if (text.size() > kProviderEvidenceStringMaxBytes) {
            result.reject(std::string(path) + "/" + std::to_string(index),
                "string_too_long", "string exceeds the 65536-byte evidence bound");
            continue;
        }
        const auto encoded = encoded_string_upper_bound(text);
        if (encoded == (std::numeric_limits<std::size_t>::max)() ||
            !charge_encoded_bytes(cumulative_bytes, encoded + 1U,
                kProviderEvidenceStringSetMaxBytes)) {
            result.reject(std::string(path), "encoded_size",
                "string set exceeds the 16 MiB cumulative evidence bound");
            return values;
        }
        if (!values.insert(text).second)
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
        const bool verified_empty = counts[0] == 0 && counts[1] == 0 && counts[2] == 0;
        const double expected_precision = verified_empty ? 1.0 : counts[0] + counts[1] == 0 ? 0.0 :
            static_cast<double>(counts[0]) / static_cast<double>(counts[0] + counts[1]);
        const double expected_recall = verified_empty ? 1.0 : counts[0] + counts[2] == 0 ? 0.0 :
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

void validate_fixture_record(contract_validation_result_t& result, const json& source_fixture, const json& defaults,
    std::string_view path, const std::set<std::string, std::less<>>& allowed_spdx,
    std::set<std::string, std::less<>>& identifiers,
    std::set<std::string, std::less<>>& formats,
    std::set<std::string, std::less<>>& architectures,
    std::set<std::string, std::less<>>& evidence_domains)
{
    json fixture = defaults;
    if (!fixture.is_object())
        fixture = json::object();
    if (source_fixture.is_object()) {
        for (auto iterator = source_fixture.begin(); iterator != source_fixture.end(); ++iterator)
            fixture[iterator.key()] = iterator.value();
    }
    if (!fixture.contains("container_chain") && fixture.contains("format") && fixture.at("format").is_string())
        fixture["container_chain"] = json::array({fixture.at("format")});
    require_closed_object(result, fixture, path,
        {"id", "source", "license", "artifact_binding", "format", "container_chain", "architecture", "architecture_identity", "mode", "endian",
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
            {"status", "algorithm", "content_hash_required", "recipes_sha256",
             "materializer_sha256", "ground_truth_sha256"});
        if (require_string(result, *binding, std::string(path) + "/artifact_binding", "status") &&
            binding->at("status").get<std::string>() != "deterministic_recipe")
            result.reject(std::string(path) + "/artifact_binding/status", "binding_status",
                "only deterministic_recipe is allowed in a bound source manifest");
        if (require_string(result, *binding, std::string(path) + "/artifact_binding", "algorithm") &&
            binding->at("algorithm").get<std::string>() != "sha256")
            result.reject(std::string(path) + "/artifact_binding/algorithm", "hash_algorithm",
                "SHA-256 is required");
        require_boolean(result, *binding, std::string(path) + "/artifact_binding", "content_hash_required", true);
        for (const std::string_view field : {"recipes_sha256", "materializer_sha256", "ground_truth_sha256"})
            require_sha256(result, *binding, std::string(path) + "/artifact_binding", field);
    }
    require_string(result, fixture, path, "format");
    const json* container_chain = require_field(result, fixture, path, "container_chain");
    if (container_chain)
        string_set(result, *container_chain, std::string(path) + "/container_chain", true);
    for (const std::string_view field : {"architecture", "architecture_identity", "mode", "endian"})
        require_string(result, fixture, path, field);
    if (fixture.contains("format") && is_nonempty_string(fixture.at("format")))
        formats.insert(fixture.at("format").get<std::string>());
    if (fixture.contains("architecture_identity") && is_nonempty_string(fixture.at("architecture_identity")))
        architectures.insert(fixture.at("architecture_identity").get<std::string>());
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
        "$id":"aida.c03.corpus-manifest.v2",
        "type":"object",
        "required":["schema","schema_version","corpus_id","license_policy","generator_source","materializer_source","ground_truth_source","target_execution_forbidden","fixture_defaults","required_coverage","fixtures","malformed_case_manifest"],
        "additionalProperties":false,
        "properties":{
            "schema":{"const":"aida.c03.corpus-manifest"},
            "schema_version":{"const":2},
            "corpus_id":{"type":"string","minLength":1},
            "license_policy":{"type":"object"},
            "generator_source":{"type":"object"},
            "materializer_source":{"type":"object"},
            "ground_truth_source":{"type":"object"},
            "target_execution_forbidden":{"const":true},
            "fixture_defaults":{"type":"object"},
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
        {"threshold_schema_version", 3},
        {"scorer_revision", 3},
        {"semantic_contract", {
            {"revision", 1},
            {"provider_execution_ground_truth_independent", true},
            {"entity_owned_facts", true},
            {"metric_domain_explicit_unknowns", true},
            {"determinism_schedules", json::array({"forward_entity_order", "reverse_entity_order"})}}},
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
        {"schema", "schema_version", "corpus_id", "license_policy", "generator_source", "materializer_source",
         "ground_truth_source", "target_execution_forbidden", "fixture_defaults", "required_coverage", "fixtures", "malformed_case_manifest"});
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
    for (const std::string_view source_name : {"materializer_source", "ground_truth_source"}) {
        const json* source = require_field(result, manifest, "", source_name);
        if (source) {
            const std::string path = "/" + std::string(source_name);
            require_closed_object(result, *source, path, {"path", "sha256", "license"});
            require_string(result, *source, path, "path");
            require_sha256(result, *source, path, "sha256");
            if (require_string(result, *source, path, "license") && !allowed_spdx.empty() &&
                allowed_spdx.find(source->at("license").get<std::string>()) == allowed_spdx.end())
                result.reject(path + "/license", "license_not_allowed", "fixture source license is not allowed");
        }
    }
    require_boolean(result, manifest, "", "target_execution_forbidden", true);
    json fixture_defaults = json::object();
    const json* defaults = require_field(result, manifest, "", "fixture_defaults");
    if (defaults) {
        require_closed_object(result, *defaults, "/fixture_defaults",
            {"source", "license", "artifact_binding", "semantic_facts", "resource_limits", "evidence_domains"});
        fixture_defaults = *defaults;
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
            validate_fixture_record(result, (*fixtures)[index], fixture_defaults, "/fixtures/" + std::to_string(index),
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
    std::map<std::string, std::string, std::less<>> fixture_formats;
    if (manifest.is_object() && manifest.contains("fixtures") && manifest.at("fixtures").is_array()) {
        for (const auto& fixture : manifest.at("fixtures")) {
            if (fixture.is_object() && fixture.contains("id") && is_nonempty_string(fixture.at("id"))) {
                fixture_ids.insert(fixture.at("id").get<std::string>());
                if (fixture.contains("format") && is_nonempty_string(fixture.at("format")))
                    fixture_formats.emplace(fixture.at("id").get<std::string>(), fixture.at("format").get<std::string>());
            }
        }
    }
    require_closed_object(result, malformed_cases, "",
        {"schema", "schema_version", "source", "license", "target_execution_forbidden", "cases"});
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
    require_boolean(result, malformed_cases, "", "target_execution_forbidden", true);
    const json* cases = require_field(result, malformed_cases, "", "cases");
    if (!cases || !cases->is_array()) {
        if (cases)
            result.reject("/cases", "array_required", "expected an array");
        return result;
    }
    if (cases->empty())
        result.reject("/cases", "min_items", "malformed cases are required");
    const std::set<std::string, std::less<>> supported_kinds{
        "truncated", "zip_bomb", "integer_overflow", "invalid_signature", "invalid_offset", "invalid_length",
        "overlapping_range", "duplicate_identity", "endian_mismatch", "recursive_collection", "invalid_count",
        "unsupported_format", "resource_exhaustion", "invalid_checksum", "invalid_encoding", "invalid_architecture"};
    std::set<std::string, std::less<>> identifiers;
    std::set<std::string, std::less<>> covered_formats;
    std::set<std::string, std::less<>> mutations;
    for (std::size_t index = 0; index < cases->size(); ++index) {
        const auto& item = (*cases)[index];
        const std::string path = "/cases/" + std::to_string(index);
        require_closed_object(result, item, path,
            {"id", "source_fixture_id", "kind", "mutation", "expected_error_codes", "max_wall_ms", "max_private_bytes",
             "target_execution_forbidden"});
        if (require_string(result, item, path, "id") && !identifiers.insert(item.at("id").get<std::string>()).second)
            result.reject(path + "/id", "duplicate", "malformed case identifier is duplicated");
        if (require_string(result, item, path, "source_fixture_id")) {
            const auto fixture_id = item.at("source_fixture_id").get<std::string>();
            if (fixture_ids.find(fixture_id) == fixture_ids.end())
                result.reject(path + "/source_fixture_id", "unknown_fixture", "source fixture is absent from corpus manifest");
            else if (const auto format = fixture_formats.find(fixture_id); format != fixture_formats.end())
                covered_formats.insert(format->second);
        }
        if (require_string(result, item, path, "kind") && supported_kinds.find(item.at("kind").get<std::string>()) == supported_kinds.end())
            result.reject(path + "/kind", "unsupported_malformed_kind", "unsupported malformed class");
        if (require_string(result, item, path, "mutation") &&
            !mutations.insert(item.at("mutation").get<std::string>()).second)
            result.reject(path + "/mutation", "duplicate", "malformed mutation identity is duplicated");
        const json* codes = require_field(result, item, path, "expected_error_codes");
        if (codes)
            string_set(result, *codes, path + "/expected_error_codes", true);
        for (const std::string_view field : {"max_wall_ms", "max_private_bytes"}) {
            const json* limit = require_field(result, item, path, field);
            if (limit && (!is_nonnegative_integer(*limit) || limit->get<std::uint64_t>() == 0))
                result.reject(path + "/" + std::string(field), "positive_integer_required",
                    "expected a positive integer");
        }
        require_boolean(result, item, path, "target_execution_forbidden", true);
    }
    std::set<std::string, std::less<>> required_formats;
    if (manifest.is_object() && manifest.contains("required_coverage") && manifest.at("required_coverage").is_object() &&
        manifest.at("required_coverage").contains("formats"))
        required_formats = string_set(result, manifest.at("required_coverage").at("formats"),
            "/manifest/required_coverage/formats", true);
    require_set_contains(result, required_formats, covered_formats, "/cases");
    return result;
}

contract_validation_result_t validate_decompiler_provider_results(const json& evidence)
{
    contract_validation_result_t result;
    require_closed_object(result, evidence, "",
        {"schema", "schema_version", "evidence_class", "measurement_eligible",
         "analysis_mode", "target_execution_forbidden", "target_execution_observed",
         "provider_run"});
    if (!evidence.is_object())
        return result;
    if (!evidence.contains("schema") || evidence.at("schema") !=
        "aida.c03.decompiler-provider-results")
        result.reject("/schema", "schema_identity", "provider result schema identity is invalid");
    if (!evidence.contains("schema_version") || !is_nonnegative_integer(evidence.at("schema_version")) ||
        evidence.at("schema_version").get<std::uint64_t>() != 3)
        result.reject("/schema_version", "schema_version", "provider result schema version must be 3");
    if (!evidence.contains("evidence_class") || evidence.at("evidence_class") !=
        "measured_provider_output")
        result.reject("/evidence_class", "evidence_class", "provider result evidence class is invalid");
    if (!evidence.contains("analysis_mode") || evidence.at("analysis_mode") != "static_only")
        result.reject("/analysis_mode", "analysis_mode", "provider result must be static-only");
    const json* eligible = require_field(result, evidence, "", "measurement_eligible");
    if (eligible && !eligible->is_boolean())
        result.reject("/measurement_eligible", "boolean_required", "expected a boolean");
    require_boolean(result, evidence, "", "target_execution_forbidden", true);
    require_boolean(result, evidence, "", "target_execution_observed", false);
    const json* run = require_field(result, evidence, "", "provider_run");
    if (!run || !run->is_object())
        return result;
    require_closed_object(result, *run, "/provider_run",
        {"provider", "status", "status_reason", "identity", "corpus", "fixtures",
         "cancellation", "launch_audit"});
    const bool provider_valid = require_string(result, *run, "/provider_run", "provider");
    if (provider_valid) {
        const auto provider = run->at("provider").get<std::string>();
        if (provider != "aida_typed_pipeline" && provider != "ghidra_printc" &&
            provider != "aida_current")
            result.reject("/provider_run/provider", "provider_identity", "provider identity is unsupported");
    }
    const bool status_valid = require_string(result, *run, "/provider_run", "status");
    std::string status;
    if (status_valid) {
        status = run->at("status").get<std::string>();
        if (status != "measured" && status != "not_measured" && status != "failed")
            result.reject("/provider_run/status", "provider_status", "provider status is invalid");
    }
    require_string(result, *run, "/provider_run", "status_reason");
    if (eligible && eligible->is_boolean() && status_valid &&
        eligible->get<bool>() != (status == "measured"))
        result.reject("/measurement_eligible", "measurement_status_mismatch",
            "measurement eligibility must agree with provider status");
    const json* identity = require_field(result, *run, "/provider_run", "identity");
    if (identity) {
        require_closed_object(result, *identity, "/provider_run/identity",
            {"provider_build_sha256", "workers", "runtime_manifest_sha256",
             "spec_manifest_sha256", "protocol_sha256"});
        require_sha256(result, *identity, "/provider_run/identity", "provider_build_sha256");
        require_sha256(result, *identity, "/provider_run/identity", "runtime_manifest_sha256");
        require_sha256(result, *identity, "/provider_run/identity", "spec_manifest_sha256");
        require_sha256(result, *identity, "/provider_run/identity", "protocol_sha256");
        const json* workers = require_field(result, *identity, "/provider_run/identity", "workers");
        if (workers && workers->is_array()) {
            if (workers->size() > 2)
                result.reject("/provider_run/identity/workers", "worker_cardinality",
                    "provider identity allows at most two workers");
            std::set<std::string, std::less<>> roles;
            for (std::size_t index = 0; index < workers->size(); ++index) {
                const auto path = "/provider_run/identity/workers/" + std::to_string(index);
                const auto& worker = (*workers)[index];
                require_closed_object(result, worker, path,
                    {"role", "binary_sha256", "manifest_sha256"});
                if (require_string(result, worker, path, "role")) {
                    const auto role = worker.at("role").get<std::string>();
                    if (role != "native" && role != "managed")
                        result.reject(path + "/role", "worker_role", "worker role is invalid");
                    else if (!roles.insert(role).second)
                        result.reject(path + "/role", "duplicate_worker_role", "worker role is duplicated");
                }
                require_sha256(result, worker, path, "binary_sha256");
                require_sha256(result, worker, path, "manifest_sha256");
            }
        } else if (workers) {
            result.reject("/provider_run/identity/workers", "array_required", "expected an array");
        }
    }
    const json* corpus = require_field(result, *run, "/provider_run", "corpus");
    if (corpus) {
        require_closed_object(result, *corpus, "/provider_run/corpus",
            {"manifest_sha256", "recipes_sha256", "ground_truth_sha256",
             "materialization_receipt_sha256", "fixture_set_sha256"});
        for (const std::string_view field : {"manifest_sha256", "recipes_sha256",
                 "ground_truth_sha256", "materialization_receipt_sha256", "fixture_set_sha256"})
            require_sha256(result, *corpus, "/provider_run/corpus", field);
    }
    std::uint64_t provider_structured_encoded_bytes = 0;
    const auto charge_provider_structured = [&](const std::uint64_t encoded_bytes,
                                                const std::string& path) {
        if (encoded_bytes > kProviderStructuredEncodedMaxBytes -
                (std::min)(provider_structured_encoded_bytes,
                    kProviderStructuredEncodedMaxBytes)) {
            result.reject(path, "structured_cumulative_size",
                "provider structured evidence exceeds the 24 MiB cumulative bound");
            return false;
        }
        provider_structured_encoded_bytes += encoded_bytes;
        return true;
    };
    const auto validate_diagnostics = [&](const json& diagnostics, const std::string& path,
                                           const std::size_t maximum_items,
                                           const std::size_t maximum_bytes) {
        if (!diagnostics.is_array()) {
            result.reject(path, "array_required", "diagnostics must be an array");
            return;
        }
        if (diagnostics.size() > maximum_items) {
            result.reject(path, "max_items", "diagnostic count exceeds the bound");
            return;
        }
        if (!charge_provider_structured(2ULL, path))
            return;
        std::size_t cumulative_bytes = 0;
        for (std::size_t index = 0; index < diagnostics.size(); ++index) {
            const auto item_path = path + "/" + std::to_string(index);
            const auto& diagnostic = diagnostics[index];
            require_closed_object(result, diagnostic, item_path, {"code", "message", "severity"});
            const bool code_valid = require_string(result, diagnostic, item_path, "code");
            const bool message_valid = require_string(result, diagnostic, item_path, "message");
            const bool severity_valid = require_string(result, diagnostic, item_path, "severity");
            std::size_t item_bytes = 40U;
            bool item_size_valid = true;
            for (const auto field : {"code", "message", "severity"}) {
                if (!diagnostic.contains(field) || !diagnostic.at(field).is_string())
                    continue;
                const auto encoded = encoded_string_upper_bound(
                    diagnostic.at(field).get_ref<const std::string&>());
                if (encoded == (std::numeric_limits<std::size_t>::max)() ||
                    !charge_encoded_bytes(item_bytes, encoded,
                        (std::numeric_limits<std::size_t>::max)())) {
                    item_size_valid = false;
                    break;
                }
            }
            if (!item_size_valid || !charge_encoded_bytes(cumulative_bytes,
                    item_bytes, maximum_bytes)) {
                result.reject(path, "encoded_size",
                    "diagnostics exceed their cumulative evidence bound");
                return;
            }
            if (!charge_provider_structured(
                    static_cast<std::uint64_t>(item_bytes), path))
                return;
            if (!code_valid || !message_valid || !severity_valid)
                continue;
            const auto severity = diagnostic.at("severity").get<std::string>();
            if (severity != "info" && severity != "warning" && severity != "error")
                result.reject(item_path + "/severity", "diagnostic_severity",
                    "diagnostic severity is invalid");
        }
    };
    std::uint64_t provider_artifact_raw_bytes = 0;
    std::uint64_t provider_artifact_encoded_bytes = 0;
    const auto charge_artifact = [&](const std::uint64_t raw_bytes,
                                     const std::string& path) {
        if (raw_bytes > kProviderArtifactRawMaxBytes -
                (std::min)(provider_artifact_raw_bytes,
                    kProviderArtifactRawMaxBytes) ||
            raw_bytes > (std::numeric_limits<std::uint64_t>::max)() / 2ULL) {
            result.reject(path, "artifact_cumulative_size",
                "provider artifacts exceed the 24 MiB cumulative raw bound");
            return;
        }
        const auto encoded_bytes = raw_bytes * 2ULL;
        if (encoded_bytes > kProviderArtifactEncodedMaxBytes -
                (std::min)(provider_artifact_encoded_bytes,
                    kProviderArtifactEncodedMaxBytes)) {
            result.reject(path, "artifact_cumulative_size",
                "provider artifacts exceed the 48 MiB cumulative encoded bound");
            return;
        }
        provider_artifact_raw_bytes += raw_bytes;
        provider_artifact_encoded_bytes += encoded_bytes;
    };
    const auto validate_artifact = [&](const json& artifact, const std::string& path) {
        if (artifact.is_null()) {
            charge_artifact(kProviderArtifactBundleMinimumBytes, path);
            return;
        }
        require_closed_object(result, artifact, path, {"encoding", "sha256", "byte_size", "payload"});
        if (!artifact.contains("encoding") || artifact.at("encoding") != "hex")
            result.reject(path + "/encoding", "artifact_encoding", "artifact encoding must be hex");
        require_sha256(result, artifact, path, "sha256");
        const json* byte_size = require_field(result, artifact, path, "byte_size");
        bool byte_size_valid = byte_size && is_nonnegative_integer(*byte_size) &&
            byte_size->get<std::uint64_t>() >= kProviderArtifactBundleMinimumBytes &&
            byte_size->get<std::uint64_t>() <= 134217728ULL;
        if (byte_size && !byte_size_valid)
            result.reject(path + "/byte_size", "artifact_size", "artifact byte size is invalid");
        if (require_string(result, artifact, path, "payload", 268435456ULL)) {
            const auto& payload = artifact.at("payload").get_ref<const std::string&>();
            if (payload.size() > 268435456ULL || payload.size() % 2 != 0 ||
                (byte_size_valid && payload.size() !=
                    byte_size->get<std::uint64_t>() * 2ULL) ||
                !std::all_of(payload.begin(), payload.end(), [](const unsigned char value) {
                    return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f');
                }))
                result.reject(path + "/payload", "artifact_payload", "artifact hex payload is invalid");
        }
        if (byte_size_valid)
            charge_artifact(byte_size->get<std::uint64_t>(), path);
    };
    const auto validate_run = [&](const json& measured_run, const std::string& path) {
        charge_provider_structured(1536ULL, path);
        require_closed_object(result, measured_run, path,
            {"run_id", "execution_witness_sha256", "started_tick_ns", "ended_tick_ns",
             "duration_ns", "schedule", "cache_state", "outcome", "artifacts", "facts", "confidence",
             "explicit_unknowns", "readability", "diagnostics"});
        require_string(result, measured_run, path, "run_id");
        require_sha256(result, measured_run, path, "execution_witness_sha256");
        for (const std::string_view field : {"started_tick_ns", "ended_tick_ns", "duration_ns"}) {
            const json* value = require_field(result, measured_run, path, field);
            if (value && (!is_nonnegative_integer(*value) || value->get<std::uint64_t>() == 0))
                result.reject(path + "/" + std::string(field), "positive_integer_required",
                    "expected a positive integer");
        }
        const json* schedule = require_field(result, measured_run, path, "schedule");
        if (schedule && (!schedule->is_string() ||
                (schedule->get<std::string>() != "forward_entity_order" &&
                 schedule->get<std::string>() != "reverse_entity_order")))
            result.reject(path + "/schedule", "execution_schedule",
                "measured run schedule must be a supported production entity order");
        if (!measured_run.contains("cache_state") || measured_run.at("cache_state") != "cache_bypass")
            result.reject(path + "/cache_state", "cache_state", "measured runs must bypass caches");
        if (!measured_run.contains("outcome") || measured_run.at("outcome") != "success")
            result.reject(path + "/outcome", "run_outcome", "measured run outcome must be success");
        const json* artifacts = require_field(result, measured_run, path, "artifacts");
        if (artifacts) {
            require_closed_object(result, *artifacts, path + "/artifacts",
                {"provider_ir", "hir", "type_graph", "ast", "document", "printc"});
            for (const std::string_view field : {"provider_ir", "hir", "type_graph", "ast", "document", "printc"}) {
                const json* artifact = require_field(result, *artifacts, path + "/artifacts", field);
                if (artifact)
                    validate_artifact(*artifact, path + "/artifacts/" + std::string(field));
            }
        }
        const json* facts = require_field(result, measured_run, path, "facts");
        std::set<std::string, std::less<>> fact_ids;
        std::uint64_t fact_and_unknown_items = 0;
        std::uint64_t fact_and_unknown_encoded_bytes = 0;
        const auto charge_fact_values = [&](const std::set<std::string, std::less<>>& values,
                                            const std::string& values_path) {
            for (const auto& value : values) {
                const auto encoded_upper = encoded_string_upper_bound(value);
                if (encoded_upper == (std::numeric_limits<std::size_t>::max)() ||
                    encoded_upper > (std::numeric_limits<std::uint64_t>::max)() - 1ULL) {
                    result.reject(values_path, "encoded_size",
                        "fact evidence size overflowed");
                    return false;
                }
                const auto encoded = static_cast<std::uint64_t>(encoded_upper) + 1ULL;
                if (fact_and_unknown_items >= kProviderEvidenceStringSetMaxItems ||
                    encoded > kProviderEvidenceStringSetMaxBytes -
                        (std::min)(fact_and_unknown_encoded_bytes,
                            static_cast<std::uint64_t>(kProviderEvidenceStringSetMaxBytes))) {
                    result.reject(values_path, "cumulative_size",
                        "facts and explicit unknowns exceed their shared cumulative bound");
                    return false;
                }
                if (!charge_provider_structured(encoded, values_path))
                    return false;
                ++fact_and_unknown_items;
                fact_and_unknown_encoded_bytes += encoded;
            }
            return true;
        };
        if (facts) {
            require_closed_object(result, *facts, path + "/facts",
                {"entities", "calls", "fields", "locals", "parameters", "cfg_edges",
                 "control_structures", "exception_regions", "types", "source_coordinates"});
            for (const std::string_view field : {"entities", "calls", "fields", "locals", "parameters",
                     "cfg_edges", "control_structures", "exception_regions", "types", "source_coordinates"}) {
                const json* values = require_field(result, *facts, path + "/facts", field);
                if (values) {
                    const auto found = string_set(result, *values,
                        path + "/facts/" + std::string(field), false);
                    if (charge_fact_values(found,
                            path + "/facts/" + std::string(field)))
                        fact_ids.insert(found.begin(), found.end());
                }
            }
        }
        const json* confidence = require_field(result, measured_run, path, "confidence");
        if (confidence && confidence->is_object()) {
            if (confidence->size() > kProviderEvidenceStringSetMaxItems) {
                result.reject(path + "/confidence", "max_properties",
                    "confidence exceeds the 65536-property evidence bound");
            } else {
                std::size_t cumulative_bytes = 0;
                for (auto iterator = confidence->begin(); iterator != confidence->end(); ++iterator) {
                    if (iterator.key().empty() ||
                        iterator.key().size() > kProviderEvidenceStringMaxBytes) {
                        result.reject(path + "/confidence", "property_name",
                            "confidence property name violates its evidence bound");
                        continue;
                    }
                    const auto encoded = encoded_string_upper_bound(iterator.key());
                    if (encoded == (std::numeric_limits<std::size_t>::max)() ||
                        encoded > (std::numeric_limits<std::size_t>::max)() - 34U ||
                        !charge_encoded_bytes(cumulative_bytes, encoded + 34U,
                            kProviderEvidenceStringSetMaxBytes)) {
                        result.reject(path + "/confidence", "encoded_size",
                            "confidence exceeds the 16 MiB cumulative evidence bound");
                        break;
                    }
                    if (!charge_provider_structured(
                            static_cast<std::uint64_t>(encoded + 34U),
                            path + "/confidence"))
                        break;
                    if (fact_ids.find(iterator.key()) == fact_ids.end() || !is_ratio(*iterator))
                        result.reject(path + "/confidence/" + iterator.key(), "confidence_binding",
                            "confidence must bind a measured fact with a finite ratio");
                }
            }
            if (confidence->size() != fact_ids.size())
                result.reject(path + "/confidence", "confidence_coverage",
                    "confidence must cover every measured fact exactly");
        } else if (confidence) {
            result.reject(path + "/confidence", "object_required", "expected an object");
        }
        const json* unknowns = require_field(result, measured_run, path, "explicit_unknowns");
        if (unknowns) {
            std::set<std::string, std::less<>> allowed;
            for (const auto metric : kQualityMetrics)
                allowed.emplace(metric);
            require_closed_object(result, *unknowns, path + "/explicit_unknowns",
                {"typed_entities", "calls", "fields", "locals", "parameters", "cfg",
                 "control_structures", "exception_regions", "type_correctness", "source_coordinates"});
            if (unknowns->is_object()) {
                for (const auto metric : kQualityMetrics) {
                    const auto values_path = path + "/explicit_unknowns/" + std::string(metric);
                    const json* values = require_field(result, *unknowns,
                        path + "/explicit_unknowns", metric);
                    if (!values)
                        continue;
                    const auto found = string_set(result, *values, values_path, false);
                    charge_fact_values(found, values_path);
                }
                for (auto iterator = unknowns->begin(); iterator != unknowns->end(); ++iterator) {
                    if (allowed.find(iterator.key()) == allowed.end())
                        result.reject(path + "/explicit_unknowns/" + iterator.key(),
                            "unknown_metric_domain", "explicit unknown metric domain is invalid");
                }
            }
        }
        const json* readability = require_field(result, measured_run, path, "readability");
        if (readability) {
            require_closed_object(result, *readability, path + "/readability",
                {"declaration_count", "max_expression_depth", "max_control_nesting",
                 "dead_placeholder_count", "cast_count", "fabricated_body_count",
                 "symbol_count", "named_symbol_count"});
            for (const std::string_view field : {"declaration_count", "max_expression_depth",
                     "max_control_nesting", "dead_placeholder_count", "cast_count",
                     "fabricated_body_count", "symbol_count", "named_symbol_count"}) {
                const json* value = require_field(result, *readability, path + "/readability", field);
                if (value && !is_nonnegative_integer(*value))
                    result.reject(path + "/readability/" + std::string(field), "nonnegative_integer_required",
                        "expected a nonnegative integer");
            }
            if (readability->contains("fabricated_body_count") &&
                is_nonnegative_integer(readability->at("fabricated_body_count")) &&
                readability->at("fabricated_body_count").get<std::uint64_t>() != 0)
                result.reject(path + "/readability/fabricated_body_count", "fabricated_body",
                    "fabricated pseudocode bodies are forbidden");
        }
        const json* diagnostics = require_field(result, measured_run, path, "diagnostics");
        if (diagnostics)
            validate_diagnostics(*diagnostics, path + "/diagnostics",
                kProviderRunDiagnosticMaxItems, kProviderRunDiagnosticMaxBytes);
    };
    const json* fixtures = require_field(result, *run, "/provider_run", "fixtures");
    if (fixtures && fixtures->is_array()) {
        if (fixtures->empty() || fixtures->size() > 512)
            result.reject("/provider_run/fixtures", "fixture_cardinality", "fixture count is invalid");
        std::set<std::string, std::less<>> ids;
        for (std::size_t index = 0; index < fixtures->size(); ++index) {
            const auto path = "/provider_run/fixtures/" + std::to_string(index);
            const auto& fixture = (*fixtures)[index];
            require_closed_object(result, fixture, path,
                {"id", "status", "status_reason", "artifact_sha256", "artifact_size",
                 "format", "architecture", "mode", "endian", "runs"});
            if (require_string(result, fixture, path, "id") &&
                !ids.insert(fixture.at("id").get<std::string>()).second)
                result.reject(path + "/id", "duplicate_fixture", "fixture identifier is duplicated");
            std::string fixture_status;
            if (require_string(result, fixture, path, "status")) {
                fixture_status = fixture.at("status").get<std::string>();
                if (fixture_status != "measured" && fixture_status != "not_applicable" &&
                    fixture_status != "failed")
                    result.reject(path + "/status", "fixture_status", "fixture status is invalid");
            }
            require_string(result, fixture, path, "status_reason");
            require_sha256(result, fixture, path, "artifact_sha256");
            const json* artifact_size = require_field(result, fixture, path, "artifact_size");
            if (artifact_size && (!is_nonnegative_integer(*artifact_size) ||
                artifact_size->get<std::uint64_t>() == 0))
                result.reject(path + "/artifact_size", "positive_integer_required",
                    "artifact size must be positive");
            for (const std::string_view field : {"format", "architecture", "mode", "endian"})
                require_string(result, fixture, path, field);
            if (fixture.contains("endian") && fixture.at("endian").is_string()) {
                const auto endian = fixture.at("endian").get<std::string>();
                if (endian != "little" && endian != "big" && endian != "mixed")
                    result.reject(path + "/endian", "endian", "fixture endian is invalid");
            }
            const json* runs = require_field(result, fixture, path, "runs");
            if (runs && runs->is_array()) {
                const std::size_t expected = fixture_status == "measured" ? 2U : 0U;
                if (runs->size() != expected)
                    result.reject(path + "/runs", "run_cardinality",
                        "fixture run cardinality does not match its status");
                for (std::size_t run_index = 0; run_index < runs->size(); ++run_index)
                    validate_run((*runs)[run_index], path + "/runs/" + std::to_string(run_index));
                if (fixture_status == "measured" && runs->size() == 2U &&
                    (*runs)[0].is_object() && (*runs)[1].is_object() &&
                    (*runs)[0].contains("schedule") && (*runs)[1].contains("schedule") &&
                    (*runs)[0].at("schedule").is_string() && (*runs)[1].at("schedule").is_string()) {
                    const std::set<std::string, std::less<>> schedules{
                        (*runs)[0].at("schedule").get<std::string>(),
                        (*runs)[1].at("schedule").get<std::string>()};
                    if (schedules != std::set<std::string, std::less<>>{
                            "forward_entity_order", "reverse_entity_order"})
                        result.reject(path + "/runs", "schedule_variation",
                            "measured determinism runs must execute both entity orders");
                }
            } else if (runs) {
                result.reject(path + "/runs", "array_required", "expected an array");
            }
        }
    } else if (fixtures) {
        result.reject("/provider_run/fixtures", "array_required", "expected an array");
    }
    const json* cancellation = require_field(result, *run, "/provider_run", "cancellation");
    if (cancellation) {
        require_closed_object(result, *cancellation, "/provider_run/cancellation",
            {"requested", "status", "status_reason", "started_tick_ns", "cancel_requested_tick_ns",
             "ended_tick_ns", "latency_ns", "outcome", "diagnostics", "execution_witness_sha256"});
        require_boolean(result, *cancellation, "/provider_run/cancellation", "requested", true);
        std::string cancellation_status;
        if (require_string(result, *cancellation, "/provider_run/cancellation", "status")) {
            cancellation_status = cancellation->at("status").get<std::string>();
            if (cancellation_status != "measured" && cancellation_status != "not_measured" &&
                cancellation_status != "failed")
                result.reject("/provider_run/cancellation/status", "cancellation_status",
                    "cancellation status is invalid");
        }
        require_string(result, *cancellation, "/provider_run/cancellation", "status_reason");
        for (const std::string_view field : {"started_tick_ns", "cancel_requested_tick_ns",
                 "ended_tick_ns", "latency_ns"}) {
            const json* value = require_field(result, *cancellation, "/provider_run/cancellation", field);
            if (value && !is_nonnegative_integer(*value))
                result.reject("/provider_run/cancellation/" + std::string(field),
                    "nonnegative_integer_required", "expected a nonnegative integer");
        }
        std::string cancellation_outcome;
        if (require_string(result, *cancellation, "/provider_run/cancellation", "outcome")) {
            cancellation_outcome = cancellation->at("outcome").get<std::string>();
            if (cancellation_outcome != "cancelled" &&
                cancellation_outcome != "completed_before_cancel" &&
                cancellation_outcome != "provider_failure")
                result.reject("/provider_run/cancellation/outcome", "cancellation_outcome",
                    "cancellation outcome is invalid");
        }
        if (cancellation_status == "measured") {
            const auto timing_valid = [&]() {
                for (const std::string_view field : {"started_tick_ns", "cancel_requested_tick_ns",
                         "ended_tick_ns", "latency_ns"}) {
                    if (!cancellation->contains(std::string(field)) ||
                        !is_nonnegative_integer(cancellation->at(std::string(field))))
                        return false;
                }
                const auto started = cancellation->at("started_tick_ns").get<std::uint64_t>();
                const auto requested = cancellation->at("cancel_requested_tick_ns").get<std::uint64_t>();
                const auto ended = cancellation->at("ended_tick_ns").get<std::uint64_t>();
                const auto latency = cancellation->at("latency_ns").get<std::uint64_t>();
                return started != 0 && requested >= started && ended >= requested &&
                    ended - requested == latency && latency <= 250ULL * 1000ULL * 1000ULL;
            }();
            if (!timing_valid || cancellation_outcome != "cancelled")
                result.reject("/provider_run/cancellation", "measured_cancellation",
                    "measured cancellation must be observed with coherent timing within 250 ms");
        }
        const json* diagnostics = require_field(result, *cancellation,
            "/provider_run/cancellation", "diagnostics");
        if (diagnostics)
            validate_diagnostics(*diagnostics, "/provider_run/cancellation/diagnostics",
                kProviderCancellationDiagnosticMaxItems,
                kProviderCancellationDiagnosticMaxBytes);
        require_sha256(result, *cancellation, "/provider_run/cancellation",
            "execution_witness_sha256");
    }
    const json* launch_audit = require_field(result, *run, "/provider_run", "launch_audit");
    if (launch_audit && launch_audit->is_array()) {
        if (launch_audit->size() > 128)
            result.reject("/provider_run/launch_audit", "max_items", "launch audit exceeds its bound");
        for (std::size_t index = 0; index < launch_audit->size(); ++index) {
            const auto path = "/provider_run/launch_audit/" + std::to_string(index);
            const auto& launch = (*launch_audit)[index];
            require_closed_object(result, launch, path, {"image_sha256", "image_role", "permitted"});
            require_sha256(result, launch, path, "image_sha256");
            if (!launch.contains("image_role") || launch.at("image_role") != "verified_worker")
                result.reject(path + "/image_role", "launch_role", "only verified workers may be launched");
            require_boolean(result, launch, path, "permitted", true);
        }
    } else if (launch_audit) {
        result.reject("/provider_run/launch_audit", "array_required", "expected an array");
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
    std::map<std::string, std::string, std::less<>> binding_hashes;
    std::map<std::string, std::string, std::less<>> binding_kinds;
    if (provenance) {
        require_closed_object(result, *provenance, "/provenance",
            {"authorization_id", "harness_build_sha256", "scorer_build_sha256", "corpus_manifest_sha256",
             "recipes_sha256", "ground_truth_sha256", "materialization_receipt_sha256", "harness_binding_id",
             "scorer_binding_id", "corpus_manifest_binding_id", "recipes_binding_id", "ground_truth_binding_id",
             "materialization_receipt_binding_id", "evidence_bindings", "provider_builds"});
        require_string(result, *provenance, "/provenance", "authorization_id");
        require_sha256(result, *provenance, "/provenance", "harness_build_sha256");
        require_sha256(result, *provenance, "/provenance", "scorer_build_sha256");
        const json* bindings = require_field(result, *provenance, "/provenance", "evidence_bindings");
        if (bindings && bindings->is_array()) {
            if (bindings->empty())
                result.reject("/provenance/evidence_bindings", "min_items", "file hash bindings are required");
            for (std::size_t index = 0; index < bindings->size(); ++index) {
                const auto& binding = (*bindings)[index];
                const std::string path = "/provenance/evidence_bindings/" + std::to_string(index);
                require_closed_object(result, binding, path, {"id", "kind", "path", "sha256", "max_bytes"});
                if (require_string(result, binding, path, "id") && require_sha256(result, binding, path, "sha256") &&
                    !binding_hashes.emplace(binding.at("id").get<std::string>(), binding.at("sha256").get<std::string>()).second)
                    result.reject(path + "/id", "duplicate_binding", "evidence binding identifier is duplicated");
                const bool kind_valid = require_string(result, binding, path, "kind");
                if (kind_valid && binding.contains("id") && is_nonempty_string(binding.at("id")))
                    binding_kinds.emplace(binding.at("id").get<std::string>(), binding.at("kind").get<std::string>());
                if (require_string(result, binding, path, "path")) {
                    const auto value = binding.at("path").get<std::string>();
                    if (value.find("..") != std::string::npos || (!value.empty() && (value.front() == '/' || value.front() == '\\')) ||
                        value.find(':') != std::string::npos)
                        result.reject(path + "/path", "path_scope", "evidence binding path must be repository-relative");
                }
                const json* max_bytes = require_field(result, binding, path, "max_bytes");
                if (max_bytes && (!is_nonnegative_integer(*max_bytes) || max_bytes->get<std::uint64_t>() == 0 ||
                    max_bytes->get<std::uint64_t>() > 4ULL * 1024ULL * 1024ULL * 1024ULL))
                    result.reject(path + "/max_bytes", "bounded_positive_integer_required", "evidence byte limit is invalid");
            }
        } else if (bindings) {
            result.reject("/provenance/evidence_bindings", "array_required", "expected an array");
        }
        const std::array<std::array<std::string_view, 3>, 6> core_bindings{
            std::array<std::string_view, 3>{"harness_binding_id", "harness_build_sha256", "harness_build"},
            std::array<std::string_view, 3>{"scorer_binding_id", "scorer_build_sha256", "scorer_build"},
            std::array<std::string_view, 3>{"corpus_manifest_binding_id", "corpus_manifest_sha256", "corpus_manifest"},
            std::array<std::string_view, 3>{"recipes_binding_id", "recipes_sha256", "corpus_recipes"},
            std::array<std::string_view, 3>{"ground_truth_binding_id", "ground_truth_sha256", "corpus_ground_truth"},
            std::array<std::string_view, 3>{"materialization_receipt_binding_id", "materialization_receipt_sha256",
                "materialization_receipt"}};
        std::set<std::string, std::less<>> core_binding_ids;
        for (const auto& expected : core_bindings) {
            const bool id_valid = require_string(result, *provenance, "/provenance", expected[0]);
            const bool hash_valid = require_sha256(result, *provenance, "/provenance", expected[1]);
            if (!id_valid || !hash_valid)
                continue;
            const auto id = provenance->at(std::string(expected[0])).get<std::string>();
            if (!core_binding_ids.insert(id).second)
                result.reject("/provenance/" + std::string(expected[0]), "binding_overlap",
                    "quality core evidence bindings must be distinct");
            const auto hash = binding_hashes.find(id);
            if (hash == binding_hashes.end() || hash->second != provenance->at(std::string(expected[1])))
                result.reject("/provenance/" + std::string(expected[0]), "binding_hash_mismatch",
                    "quality core evidence hash does not match its file binding");
            const auto kind = binding_kinds.find(id);
            if (kind == binding_kinds.end() || kind->second != expected[2])
                result.reject("/provenance/" + std::string(expected[0]), "binding_kind_mismatch",
                    "quality core evidence binding has the wrong kind");
        }
        const json* provider_builds = require_field(result, *provenance, "/provenance", "provider_builds");
        if (provider_builds && provider_builds->is_array()) {
            if (provider_builds->empty())
                result.reject("/provenance/provider_builds", "min_items", "provider build evidence is required");
            for (std::size_t index = 0; index < provider_builds->size(); ++index) {
                const auto& provider = (*provider_builds)[index];
                const std::string path = "/provenance/provider_builds/" + std::to_string(index);
                require_closed_object(result, provider, path,
                    {"provider", "build_sha256", "build_binding_id", "workers",
                     "runtime_manifest_sha256", "runtime_manifest_binding_id",
                     "spec_manifest_sha256", "spec_manifest_binding_id", "protocol_sha256",
                     "result_sha256", "result_binding_id"});
                if (require_string(result, provider, path, "provider") &&
                    !providers.insert(provider.at("provider").get<std::string>()).second)
                    result.reject(path + "/provider", "duplicate_provider", "provider build evidence is duplicated");
                if (require_sha256(result, provider, path, "build_sha256") &&
                    provider.contains("provider") && is_nonempty_string(provider.at("provider")))
                    provider_build_hashes.emplace(provider.at("provider").get<std::string>(),
                        provider.at("build_sha256").get<std::string>());
                require_sha256(result, provider, path, "runtime_manifest_sha256");
                require_sha256(result, provider, path, "spec_manifest_sha256");
                require_sha256(result, provider, path, "protocol_sha256");
                require_sha256(result, provider, path, "result_sha256");
                for (const auto binding : std::array<std::pair<std::string_view, std::string_view>, 4>{
                         std::pair<std::string_view, std::string_view>{"build_binding_id", "build_sha256"},
                         {"runtime_manifest_binding_id", "runtime_manifest_sha256"},
                         {"spec_manifest_binding_id", "spec_manifest_sha256"},
                         {"result_binding_id", "result_sha256"}}) {
                    if (require_string(result, provider, path, binding.first)) {
                        const auto found = binding_hashes.find(provider.at(std::string(binding.first)).get<std::string>());
                        if (found == binding_hashes.end() || !provider.contains(std::string(binding.second)) ||
                            !provider.at(std::string(binding.second)).is_string() || found->second != provider.at(std::string(binding.second)))
                            result.reject(path + "/" + std::string(binding.first), "binding_hash_mismatch",
                                "provider hash does not match its file evidence binding");
                    }
                }
                const std::array<std::pair<std::string_view, std::string_view>, 4> expected_kinds{
                    std::pair<std::string_view, std::string_view>{"build_binding_id", "provider_build"},
                    {"runtime_manifest_binding_id", "runtime_manifest"},
                    {"spec_manifest_binding_id", "spec_manifest"},
                    {"result_binding_id", "provider_results"}};
                std::set<std::string, std::less<>> provider_binding_ids;
                for (const auto& expected : expected_kinds) {
                    if (!provider.contains(std::string(expected.first)) ||
                        !is_nonempty_string(provider.at(std::string(expected.first))))
                        continue;
                    const auto id = provider.at(std::string(expected.first)).get<std::string>();
                    if (!provider_binding_ids.insert(id).second)
                        result.reject(path + "/" + std::string(expected.first), "binding_overlap",
                            "provider build, manifest, and result bindings must be distinct");
                    const auto kind = binding_kinds.find(id);
                    if (kind == binding_kinds.end() || kind->second != expected.second)
                        result.reject(path + "/" + std::string(expected.first), "binding_kind_mismatch",
                            "provider evidence binding has the wrong kind");
                }
                const json* workers = require_field(result, provider, path, "workers");
                if (workers && workers->is_array()) {
                    if (workers->size() > 2)
                        result.reject(path + "/workers", "worker_cardinality",
                            "provider build evidence allows at most two workers");
                    std::set<std::string, std::less<>> roles;
                    for (std::size_t worker_index = 0; worker_index < workers->size(); ++worker_index) {
                        const auto worker_path = path + "/workers/" + std::to_string(worker_index);
                        const auto& worker = (*workers)[worker_index];
                        require_closed_object(result, worker, worker_path,
                            {"role", "binary_sha256", "manifest_sha256", "binary_binding_id",
                             "manifest_binding_id"});
                        if (require_string(result, worker, worker_path, "role")) {
                            const auto role = worker.at("role").get<std::string>();
                            if ((role != "native" && role != "managed") || !roles.insert(role).second)
                                result.reject(worker_path + "/role", "worker_role",
                                    "worker role is invalid or duplicated");
                        }
                        require_sha256(result, worker, worker_path, "binary_sha256");
                        require_sha256(result, worker, worker_path, "manifest_sha256");
                        for (const auto worker_binding :
                            std::array<std::tuple<std::string_view, std::string_view, std::string_view>, 2>{
                                std::tuple<std::string_view, std::string_view, std::string_view>{
                                    "binary_binding_id", "binary_sha256", "worker_binary"},
                                {"manifest_binding_id", "manifest_sha256", "worker_manifest"}}) {
                            const auto binding_field = std::get<0>(worker_binding);
                            const auto hash_field = std::get<1>(worker_binding);
                            const auto kind = std::get<2>(worker_binding);
                            if (!require_string(result, worker, worker_path, binding_field))
                                continue;
                            const auto id = worker.at(std::string(binding_field)).get<std::string>();
                            if (!provider_binding_ids.insert(id).second)
                                result.reject(worker_path + "/" + std::string(binding_field),
                                    "binding_overlap", "provider evidence bindings must be distinct");
                            const auto hash = binding_hashes.find(id);
                            if (hash == binding_hashes.end() ||
                                !worker.contains(std::string(hash_field)) ||
                                !worker.at(std::string(hash_field)).is_string() ||
                                hash->second != worker.at(std::string(hash_field)).get<std::string>())
                                result.reject(worker_path + "/" + std::string(binding_field),
                                    "binding_hash_mismatch", "worker hash differs from its file binding");
                            const auto observed_kind = binding_kinds.find(id);
                            if (observed_kind == binding_kinds.end() || observed_kind->second != kind)
                                result.reject(worker_path + "/" + std::string(binding_field),
                                    "binding_kind_mismatch", "worker binding has the wrong kind");
                        }
                    }
                } else if (workers) {
                    result.reject(path + "/workers", "array_required", "expected an array");
                }
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
        if (provenance && corpus->contains("manifest_sha256") && is_sha256(corpus->at("manifest_sha256")) &&
            provenance->contains("corpus_manifest_sha256") &&
            corpus->at("manifest_sha256") != provenance->at("corpus_manifest_sha256"))
            result.reject("/corpus/manifest_sha256", "binding_hash_mismatch",
                "corpus manifest hash differs from provenance");
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
                    {"id", "artifact_sha256", "source_provenance_sha256", "semantic_facts_sha256", "artifact_binding_id",
                     "source_binding_id", "format", "architecture", "mode", "endian"});
                if (require_string(result, fixture, path, "id") &&
                    !fixture_ids.insert(fixture.at("id").get<std::string>()).second)
                    result.reject(path + "/id", "duplicate_fixture", "fixture evidence is duplicated");
                for (const std::string_view field : {"artifact_sha256", "source_provenance_sha256", "semantic_facts_sha256"})
                    require_sha256(result, fixture, path, field);
                for (const auto binding : std::array<std::pair<std::string_view, std::string_view>, 2>{
                         std::pair<std::string_view, std::string_view>{"artifact_binding_id", "artifact_sha256"},
                         {"source_binding_id", "source_provenance_sha256"}}) {
                    if (require_string(result, fixture, path, binding.first)) {
                        const auto found = binding_hashes.find(fixture.at(std::string(binding.first)).get<std::string>());
                        if (found == binding_hashes.end() || !fixture.contains(std::string(binding.second)) ||
                            !fixture.at(std::string(binding.second)).is_string() || found->second != fixture.at(std::string(binding.second)))
                            result.reject(path + "/" + std::string(binding.first), "binding_hash_mismatch",
                                "fixture hash does not match its file evidence binding");
                    }
                }
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
            std::set<std::string, std::less<>> schedules;
            std::set<std::string, std::less<>> cache_states;
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
                    is_nonempty_string(run.at("cache_state"))) {
                    schedule_cache_pairs.insert(run.at("schedule").get<std::string>() + "\n" + run.at("cache_state").get<std::string>());
                    schedules.insert(run.at("schedule").get<std::string>());
                    cache_states.insert(run.at("cache_state").get<std::string>());
                }
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
            if (runs->size() >= 2 && (schedules != std::set<std::string, std::less<>>{
                    "forward_entity_order", "reverse_entity_order"} ||
                cache_states != std::set<std::string, std::less<>>{"cache_bypass"}))
                result.reject("/determinism/runs", "determinism_schedule_contract",
                    "determinism must bind both production entity orders with cache bypass");
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
    std::string receipt_hash_error;
    if (!verify_canonical_receipt_hash(receipt, "receipt_sha256", receipt_hash_error))
        result.reject("/receipt_sha256", "receipt_hash", receipt_hash_error);
    return result;
}

contract_validation_result_t validate_decompiler_quality_receipt_files(const json& receipt,
    const std::filesystem::path& repository_root)
{
    auto result = validate_decompiler_quality_receipt(receipt);
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
        const auto observed = sha256_repository_evidence_file(repository_root,
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
