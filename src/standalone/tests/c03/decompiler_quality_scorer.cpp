#include "decompiler_quality_scorer.hpp"

#include "assertion_telemetry/assertion_telemetry.hpp"

#include "evidence_hash.hpp"
#include "fixture_materializer.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace aida::analysis::c03
{
namespace
{
    constexpr std::array<std::string_view, 10> k_metrics{"typed_entities", "calls", "fields", "locals",
        "parameters", "cfg", "control_structures", "exception_regions", "type_correctness", "source_coordinates"};

    struct scorer_error_t : std::runtime_error
    {
        using std::runtime_error::runtime_error;
    };

    struct binding_t
    {
        quality_file_binding_request_t request;
        std::string sha256;
    };

    using binding_map_t = std::map<std::string, binding_t, std::less<>>;

    void require(bool condition, std::string message)
    {
		aida::analysis::c03_test::assertion_telemetry::record_assertion(
			condition, message, __FILE__, __LINE__);
        if (!condition)
            throw scorer_error_t(std::move(message));
    }

    void add_count(std::uint64_t& value, std::uint64_t increment, std::string_view label)
    {
        require(value <= std::numeric_limits<std::uint64_t>::max() - increment,
            std::string(label) + " counter overflow");
        value += increment;
    }

    void require_closed(const json& value, std::initializer_list<std::string_view> allowed,
        std::string_view label)
    {
        require(value.is_object(), std::string(label) + " must be an object");
        std::set<std::string, std::less<>> names;
        for (const auto name : allowed)
            names.emplace(name);
        for (auto iterator = value.begin(); iterator != value.end(); ++iterator)
            require(names.find(iterator.key()) != names.end(), std::string(label) + " has unknown field " + iterator.key());
    }

    std::string require_text(const json& value, std::string_view field, std::string_view label)
    {
        require(value.contains(std::string(field)) && value.at(std::string(field)).is_string() &&
            !value.at(std::string(field)).get_ref<const std::string&>().empty(),
            std::string(label) + " requires nonempty " + std::string(field));
        return value.at(std::string(field)).get<std::string>();
    }

    std::set<std::string, std::less<>> strings(const json& value, std::string_view label)
    {
        require(value.is_array(), std::string(label) + " must be an array");
        std::set<std::string, std::less<>> output;
        for (const auto& item : value) {
            require(item.is_string() && !item.get_ref<const std::string&>().empty(),
                std::string(label) + " contains an invalid fact");
            require(output.insert(item.get<std::string>()).second,
                std::string(label) + " contains a duplicate fact");
        }
        return output;
    }

    binding_map_t bind_files(const decompiler_quality_score_request_t& request)
    {
        require(!request.file_bindings.empty() && request.file_bindings.size() <= 512,
            "quality scorer requires a bounded nonempty file-binding set");
        binding_map_t bindings;
        for (const auto& binding : request.file_bindings) {
            require(!binding.id.empty() && !binding.kind.empty() && !binding.relative_path.empty() &&
                is_canonical_sha256(binding.expected_sha256) &&
                binding.maximum_bytes != 0 && binding.maximum_bytes <= 4ULL * 1024ULL * 1024ULL * 1024ULL,
                "quality file binding is incomplete or unbounded");
            const auto hash = sha256_repository_evidence_file(request.evidence_root,
                binding.relative_path, binding.maximum_bytes);
            require(hash.ok, hash.error);
            require(hash.sha256 == binding.expected_sha256,
                "quality file binding hash differs from the expected immutable identity");
            require(bindings.emplace(binding.id, binding_t{binding, hash.sha256}).second,
                "quality file binding identifier is duplicated");
        }
        return bindings;
    }

    const binding_t& binding(const binding_map_t& bindings, std::string_view id)
    {
        const auto found = bindings.find(std::string(id));
        require(found != bindings.end(), "quality evidence references an unknown file binding");
        return found->second;
    }

    json load_bound_json(const std::filesystem::path& root, const binding_t& source)
    {
        const auto path = root / std::filesystem::u8path(source.request.relative_path);
        std::error_code size_error;
        const auto size = std::filesystem::file_size(path, size_error);
        require(!size_error && size != 0 && size <= source.request.max_bytes &&
                size <= static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()),
            "bound JSON evidence is absent, empty, or oversized");
        std::ifstream stream(path, std::ios::binary);
        require(stream.good(), "bound JSON evidence cannot be opened");
        std::string bytes(static_cast<std::size_t>(size), '\0');
        stream.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        require(stream && stream.gcount() == static_cast<std::streamsize>(bytes.size()),
            "bound JSON evidence could not be read completely");
        const auto observed = sha256_evidence_bytes(bytes.data(), bytes.size());
        require(observed.ok && observed.sha256 == source.sha256,
            observed.ok ? "bound JSON bytes changed after evidence binding" : observed.error);
        try {
            return json::parse(bytes, nullptr, true, false);
        } catch (const std::exception& parse_error) {
            throw scorer_error_t(std::string("bound JSON evidence is malformed: ") +
                parse_error.what());
        }
    }

    std::map<std::string, json, std::less<>> index_by_id(const json& records, std::string_view label)
    {
        require(records.is_array() && !records.empty(), std::string(label) + " must be a nonempty array");
        std::map<std::string, json, std::less<>> output;
        for (const auto& record : records) {
            require_closed(record, {"id", "format", "architecture", "architecture_identity", "mode", "endian", "source", "facts"}, label);
            const auto id = require_text(record, "id", label);
            require(output.emplace(id, record).second, std::string(label) + " contains a duplicate identifier");
        }
        return output;
    }

    std::string fact_field(std::string_view metric)
    {
        if (metric == "typed_entities") return "entities";
        if (metric == "cfg") return "cfg_edges";
        if (metric == "type_correctness") return "types";
        return std::string(metric);
    }

    std::set<std::string, std::less<>> metric_facts(const json& facts, std::string_view metric)
    {
        require(facts.is_object(), "provider or ground-truth facts must be an object");
        const auto field = fact_field(metric);
        const auto found = facts.find(field);
        require(found != facts.end(), "provider or ground-truth facts omit required metric field: " + field);
        return strings(*found, field);
    }

    json normalized_ground_truth_records(const json& ground_truth)
    {
        require_closed(ground_truth, {"schema", "schema_version", "license", "target_execution_forbidden",
            "coordinate_contract", "source_files", "metric_fact_defaults", "metric_fact_overrides", "fixtures"},
            "ground truth");
        require(ground_truth.value("schema", std::string{}) == "aida.c03.corpus-ground-truth" &&
            ground_truth.value("schema_version", 0) == 1 && ground_truth.value("target_execution_forbidden", false),
            "quality ground truth identity or nonexecution contract is invalid");
        require(ground_truth.contains("metric_fact_defaults") && ground_truth.at("metric_fact_defaults").is_object() &&
            ground_truth.contains("metric_fact_overrides") && ground_truth.at("metric_fact_overrides").is_object(),
            "quality ground truth metric fact policy is absent");
        require(ground_truth.contains("source_files") && ground_truth.at("source_files").is_object() &&
            !ground_truth.at("source_files").empty(), "quality ground truth source hash inventory is absent");
        for (auto iterator = ground_truth.at("source_files").begin();
             iterator != ground_truth.at("source_files").end(); ++iterator)
            require(!iterator.key().empty() && iterator->is_string() &&
                is_canonical_sha256(iterator->get_ref<const std::string&>()),
                "quality ground truth source hash inventory is invalid");
        constexpr std::array<std::string_view, 4> supplemental_fields{
            "fields", "locals", "parameters", "exception_regions"};
        const auto& defaults = ground_truth.at("metric_fact_defaults");
        require_closed(defaults, {"fields", "locals", "parameters", "exception_regions"},
            "ground-truth metric defaults");
        for (const auto field : supplemental_fields) {
            require(defaults.contains(std::string(field)),
                "ground-truth metric defaults omit " + std::string(field));
            strings(defaults.at(std::string(field)), field);
        }
        const auto& source_records = ground_truth.at("fixtures");
        require(source_records.is_array() && !source_records.empty(), "ground truth fixtures must be a nonempty array");
        std::set<std::string, std::less<>> fixture_ids;
        for (const auto& record : source_records)
            require(fixture_ids.insert(require_text(record, "id", "ground truth")).second,
                "ground truth contains a duplicate identifier");
        for (auto iterator = ground_truth.at("metric_fact_overrides").begin();
             iterator != ground_truth.at("metric_fact_overrides").end(); ++iterator) {
            require(fixture_ids.find(iterator.key()) != fixture_ids.end(),
                "ground-truth metric override references an unknown fixture: " + iterator.key());
            require_closed(*iterator, {"fields", "locals", "parameters", "exception_regions"},
                "ground-truth metric override");
            for (const auto field : supplemental_fields) {
                require(iterator->contains(std::string(field)),
                    "ground-truth metric override omits " + std::string(field));
                strings(iterator->at(std::string(field)), field);
            }
        }
        json normalized = json::array();
        std::map<std::string, std::set<std::string, std::less<>>, std::less<>> aggregate;
        std::set<std::string, std::less<>> referenced_sources;
        for (const auto metric : k_metrics)
            aggregate.emplace(std::string(metric), std::set<std::string, std::less<>>{});
        for (const auto& record : source_records) {
            json normalized_record = record;
            const auto source = require_text(normalized_record, "source", "ground truth");
            require(ground_truth.at("source_files").contains(source),
                "ground-truth fixture references an unbound source file");
            referenced_sources.insert(source);
            auto& facts = normalized_record.at("facts");
            require_closed(facts, {"entities", "cfg_edges", "calls", "fields", "locals", "parameters", "types",
                "symbols", "control_structures", "exception_regions", "source_coordinates", "explicit_unknowns"},
                "ground-truth facts");
            const auto id = record.at("id").get<std::string>();
            const auto override = ground_truth.at("metric_fact_overrides").find(id);
            for (const auto field : supplemental_fields) {
                if (!facts.contains(std::string(field)))
                    facts[std::string(field)] = override == ground_truth.at("metric_fact_overrides").end() ?
                        defaults.at(std::string(field)) : override->at(std::string(field));
            }
            require(facts.contains("explicit_unknowns"), "ground-truth facts omit explicit_unknowns");
            strings(facts.at("explicit_unknowns"), "explicit_unknowns");
            for (const auto metric : k_metrics) {
                const auto values = metric_facts(facts, metric);
                aggregate.at(std::string(metric)).insert(values.begin(), values.end());
            }
            normalized.push_back(std::move(normalized_record));
        }
        for (const auto metric : k_metrics)
            require(!aggregate.at(std::string(metric)).empty(),
                "ground-truth corpus has no positive facts for metric: " + std::string(metric));
        require(referenced_sources.size() == ground_truth.at("source_files").size(),
            "ground-truth source hash inventory contains an unreferenced source file");
        return normalized;
    }

    json score_metric(const std::set<std::string, std::less<>>& expected,
        const std::set<std::string, std::less<>>& observed, std::string_view provenance_id,
        const json& confidence, const std::set<std::string, std::less<>>& explicit_unknowns)
    {
        std::uint64_t tp = 0;
        for (const auto& value : observed) {
            if (expected.find(value) != expected.end())
                ++tp;
        }
        const auto fp = static_cast<std::uint64_t>(observed.size()) - tp;
        const auto fn = static_cast<std::uint64_t>(expected.size()) - tp;
        const bool verified_empty = tp == 0 && fp == 0 && fn == 0;
        const double precision = verified_empty ? 1.0 :
            (tp + fp == 0 ? 0.0 : static_cast<double>(tp) / static_cast<double>(tp + fp));
        const double recall = verified_empty ? 1.0 :
            (tp + fn == 0 ? 0.0 : static_cast<double>(tp) / static_cast<double>(tp + fn));
        const double f1 = precision + recall == 0.0 ? 0.0 : 2.0 * precision * recall / (precision + recall);
        std::vector<double> known_confidence;
        for (const auto& fact : observed) {
            const auto found = confidence.find(fact);
            require(found != confidence.end() && found->is_number(), "observed fact lacks confidence evidence: " + fact);
            const double value = found->get<double>();
            require(std::isfinite(value) && value >= 0.0 && value <= 1.0,
                "observed fact confidence is not a finite ratio");
            known_confidence.push_back(value);
        }
        const auto known_observation_count = known_confidence.size();
        double confidence_sum = 0.0;
        double minimum_confidence = 1.0;
        for (const auto value : known_confidence) {
            confidence_sum += value;
            minimum_confidence = std::min(minimum_confidence, value);
        }
        json unknown_ids = json::array();
        for (const auto& unknown : explicit_unknowns)
            unknown_ids.push_back(unknown);
        const auto observations = static_cast<std::uint64_t>(known_observation_count + explicit_unknowns.size());
        return {{"tp", tp}, {"fp", fp}, {"fn", fn}, {"precision", precision}, {"recall", recall}, {"f1", f1},
            {"provenance_ids", json::array({std::string(provenance_id)})},
            {"confidence", {{"observation_count", observations},
                {"known_observations", known_observation_count},
                {"explicit_unknown_observations", explicit_unknowns.size()}, {"implicit_unknown_observations", 0},
                {"confidence_sum", confidence_sum}, {"mean_confidence", known_observation_count == 0 ? 1.0 :
                    confidence_sum / static_cast<double>(known_observation_count)},
                {"minimum_confidence", minimum_confidence},
                {"explicit_unknown_ratio", observations == 0 ? 0.0 :
                    static_cast<double>(explicit_unknowns.size()) / static_cast<double>(observations)},
                {"explicit_unknown_ids", std::move(unknown_ids)},
                {"provenance_ids", json::array({std::string(provenance_id)})}}}};
    }

    struct provider_score_t
    {
        std::string provider;
        std::string build_hash;
        std::string build_binding_id;
        std::string result_binding_id;
        std::string result_hash;
        std::string runtime_manifest_binding_id;
        std::string spec_manifest_binding_id;
        json worker_bindings;
        json metrics;
        json readability;
        json diagnostics;
        json determinism_runs;
        json normalized_outputs;
        json cancellation;
        json identity;
    };

    std::vector<std::uint8_t> decode_hex_payload(std::string_view payload)
    {
        require(!payload.empty() && payload.size() % 2 == 0,
            "raw provider artifact hex payload is empty or odd-sized");
        const auto nibble = [](const char value) -> std::uint8_t {
            if (value >= '0' && value <= '9')
                return static_cast<std::uint8_t>(value - '0');
            if (value >= 'a' && value <= 'f')
                return static_cast<std::uint8_t>(value - 'a' + 10);
            throw scorer_error_t("raw provider artifact contains non-canonical hex");
        };
        std::vector<std::uint8_t> bytes(payload.size() / 2U);
        for (std::size_t index = 0; index < bytes.size(); ++index)
            bytes[index] = static_cast<std::uint8_t>(
                (nibble(payload[index * 2U]) << 4U) | nibble(payload[index * 2U + 1U]));
        return bytes;
    }

    std::string validate_raw_artifact(const json& artifact, std::string_view label)
    {
        require(artifact.is_object(), std::string(label) + " raw artifact is absent");
        require_closed(artifact, {"encoding", "sha256", "byte_size", "payload"}, label);
        require(artifact.value("encoding", std::string{}) == "hex" &&
            artifact.contains("sha256") && artifact.at("sha256").is_string() &&
            is_canonical_sha256(artifact.at("sha256").get_ref<const std::string&>()) &&
            artifact.contains("byte_size") && artifact.at("byte_size").is_number_unsigned() &&
            artifact.at("byte_size").get<std::uint64_t>() != 0 &&
            artifact.at("byte_size").get<std::uint64_t>() <= 128ULL * 1024ULL * 1024ULL &&
            artifact.contains("payload") && artifact.at("payload").is_string(),
            std::string(label) + " raw artifact contract is invalid");
        const auto& payload = artifact.at("payload").get_ref<const std::string&>();
        const auto expected_size = artifact.at("byte_size").get<std::uint64_t>();
        require(expected_size <= std::numeric_limits<std::size_t>::max() / 2U &&
            payload.size() == static_cast<std::size_t>(expected_size) * 2U,
            std::string(label) + " raw artifact byte count differs from its hex payload");
        const auto bytes = decode_hex_payload(payload);
        const auto hash = sha256_evidence_bytes(bytes.data(), bytes.size());
        require(hash.ok, hash.error);
        require(hash.sha256 == artifact.at("sha256").get<std::string>(),
            std::string(label) + " raw artifact hash differs from its payload");
        return hash.sha256;
    }

    void validate_execution_witness(const json& value, std::string_view label)
    {
        require(value.is_object() && value.contains("execution_witness_sha256") &&
            value.at("execution_witness_sha256").is_string() &&
            is_canonical_sha256(value.at("execution_witness_sha256").get_ref<const std::string&>()),
            std::string(label) + " execution witness is absent");
        const auto expected = canonical_json_sha256(value, "execution_witness_sha256");
        require(expected.ok, expected.error);
        require(expected.sha256 == value.at("execution_witness_sha256").get<std::string>(),
            std::string(label) + " execution witness hash is invalid");
    }

    bool managed_only_fixture(const json& truth)
    {
        const auto architecture = truth.at("architecture_identity").get<std::string>();
        const auto format = truth.at("format").get<std::string>();
        return architecture == "jvm" || architecture == "dalvik" || format == "cli";
    }

    bool artifact_required(std::string_view provider, std::string_view artifact)
    {
        if (provider == "aida_typed_pipeline")
            return artifact != "printc";
        if (provider == "ghidra_printc")
            return true;
        return artifact == "ast" || artifact == "document";
    }

    provider_score_t score_provider(const json& provider, const binding_map_t& bindings,
        const std::filesystem::path& evidence_root,
        const std::map<std::string, json, std::less<>>& truth,
        const std::map<std::string, json, std::less<>>& materialized,
        const std::set<std::string, std::less<>>& selected_ids,
        std::string_view manifest_hash, std::string_view recipes_hash,
        std::string_view ground_truth_hash, std::string_view materialization_receipt_hash,
        std::string_view fixture_set_hash)
    {
        require_closed(provider, {"provider", "status", "status_reason", "identity", "corpus",
            "fixtures", "cancellation", "launch_audit", "build_binding_id", "result_binding_id",
            "worker_bindings", "runtime_manifest_binding_id", "spec_manifest_binding_id"},
            "provider run");
        provider_score_t score;
        score.provider = require_text(provider, "provider", "provider run");
        score.build_binding_id = require_text(provider, "build_binding_id", "provider run");
        score.result_binding_id = require_text(provider, "result_binding_id", "provider run");
        const auto& build = binding(bindings, score.build_binding_id);
        const auto& results = binding(bindings, score.result_binding_id);
        require(build.request.kind == "provider_build" &&
            results.request.kind == "provider_results", "provider build, manifest, or result binding kind mismatch");
        require(score.build_binding_id != score.result_binding_id,
            "provider build and result binding identifiers overlap");
        score.build_hash = build.sha256;
        score.result_hash = results.sha256;
        std::set<std::string, std::less<>> forbidden_artifact_hashes;
        for (const auto& pair : bindings) {
            if (pair.second.request.kind == "corpus_ground_truth" ||
                pair.second.request.kind == "materialization_receipt" ||
                pair.second.request.kind == "source_ground_truth" ||
                pair.second.request.kind == "materialized_artifact") {
                forbidden_artifact_hashes.insert(pair.second.sha256);
                require(pair.second.sha256 != score.result_hash,
                    "provider result file collides with source, ground-truth, or artifact evidence");
            }
        }
        const auto result_evidence = load_bound_json(evidence_root, results);
        const auto provider_validation = validate_decompiler_provider_results(result_evidence);
        require(provider_validation.valid, provider_validation.summary());
        require(result_evidence.at("measurement_eligible").get<bool>() &&
            result_evidence.at("provider_run").at("status") == "measured",
            "nonmeasurement provider evidence cannot produce a quality receipt");
        json bound_run = provider;
        bound_run.erase("build_binding_id");
        bound_run.erase("result_binding_id");
        bound_run.erase("worker_bindings");
        bound_run.erase("runtime_manifest_binding_id");
        bound_run.erase("spec_manifest_binding_id");
        if (result_evidence.at("provider_run").contains("build_binding_id") ||
            result_evidence.at("provider_run").contains("result_binding_id") ||
            result_evidence.at("provider_run").contains("worker_bindings") ||
            result_evidence.at("provider_run").contains("runtime_manifest_binding_id") ||
            result_evidence.at("provider_run").contains("spec_manifest_binding_id"))
            require(false, "provider result file must not inject receipt binding identifiers");
        require(result_evidence.at("provider_run") == bound_run,
            "provider run differs from its hash-bound result evidence");
        score.identity = provider.at("identity");
        require(score.identity.at("provider_build_sha256") == score.build_hash,
            "provider build identity differs from its executable binding");
        const auto runtime_binding_id = require_text(provider, "runtime_manifest_binding_id", "provider run");
        const auto spec_binding_id = require_text(provider, "spec_manifest_binding_id", "provider run");
        score.runtime_manifest_binding_id = runtime_binding_id;
        score.spec_manifest_binding_id = spec_binding_id;
        score.worker_bindings = provider.at("worker_bindings");
        const auto& runtime_binding = binding(bindings, runtime_binding_id);
        const auto& spec_binding = binding(bindings, spec_binding_id);
        require(runtime_binding.request.kind == "runtime_manifest" &&
            spec_binding.request.kind == "spec_manifest" &&
            score.identity.at("runtime_manifest_sha256") == runtime_binding.sha256 &&
            score.identity.at("spec_manifest_sha256") == spec_binding.sha256,
            "provider runtime or specification identity differs from its file binding");
        require(provider.contains("worker_bindings") && provider.at("worker_bindings").is_array(),
            "provider worker bindings are absent");
        std::map<std::string, std::pair<std::string, std::string>, std::less<>> identity_workers;
        for (const auto& worker : score.identity.at("workers")) {
            const auto role = worker.at("role").get<std::string>();
            require(identity_workers.emplace(role, std::pair{
                worker.at("binary_sha256").get<std::string>(),
                worker.at("manifest_sha256").get<std::string>()}).second,
                "provider identity repeats a worker role");
        }
        if (score.provider == "aida_typed_pipeline")
            require(identity_workers.size() == 2 &&
                identity_workers.find("native") != identity_workers.end() &&
                identity_workers.find("managed") != identity_workers.end(),
                "typed pipeline identity must bind both production workers");
        else if (score.provider == "ghidra_printc")
            require(identity_workers.size() == 1 &&
                identity_workers.find("native") != identity_workers.end(),
                "Ghidra PrintC identity must bind only the native worker");
        else
            require(identity_workers.empty(),
                "current AiDA in-process baseline must not claim a worker identity");
        std::set<std::string, std::less<>> worker_binding_roles;
        for (const auto& worker : provider.at("worker_bindings")) {
            require_closed(worker, {"role", "binary_binding_id", "manifest_binding_id"},
                "provider worker binding");
            const auto role = require_text(worker, "role", "provider worker binding");
            const auto binary_id = require_text(worker, "binary_binding_id", "provider worker binding");
            const auto worker_manifest_id = require_text(worker, "manifest_binding_id", "provider worker binding");
            require(worker_binding_roles.insert(role).second,
                "provider worker binding role is duplicated");
            const auto found = identity_workers.find(role);
            require(found != identity_workers.end(), "provider worker binding has no identity row");
            const auto& binary = binding(bindings, binary_id);
            const auto& worker_manifest = binding(bindings, worker_manifest_id);
            require(binary.request.kind == "worker_binary" &&
                worker_manifest.request.kind == "worker_manifest" &&
                found->second.first == binary.sha256 &&
                found->second.second == worker_manifest.sha256,
                "provider worker identity differs from its executable or manifest binding");
        }
        require(worker_binding_roles.size() == identity_workers.size(),
            "provider worker binding set is incomplete");
        const auto& corpus = provider.at("corpus");
        require(corpus.at("manifest_sha256") == manifest_hash &&
            corpus.at("recipes_sha256") == recipes_hash &&
            corpus.at("ground_truth_sha256") == ground_truth_hash &&
            corpus.at("materialization_receipt_sha256") == materialization_receipt_hash &&
            corpus.at("fixture_set_sha256") == fixture_set_hash,
            "provider corpus identity differs from the scored immutable corpus");
        const auto& fixtures = provider.at("fixtures");
        require(fixtures.is_array() && fixtures.size() == selected_ids.size(),
            "provider fixture result cardinality differs from corpus selection");
        std::map<std::string, json, std::less<>> outputs;
        std::array<json, 2> deterministic_outputs{json::array(), json::array()};
        std::array<json, 2> deterministic_source_maps{json::array(), json::array()};
        std::set<std::string, std::less<>> run_ids;
        std::uint64_t unsupported = 0;
        for (const auto& fixture : fixtures) {
            const auto id = require_text(fixture, "id", "provider fixture result");
            require(selected_ids.find(id) != selected_ids.end(), "provider returned an unselected fixture");
            const auto& expected = truth.at(id);
            const auto& artifact = materialized.at(id);
            require(fixture.at("artifact_sha256") == artifact.at("artifact_sha256") &&
                fixture.at("artifact_size") == artifact.at("size_bytes") &&
                fixture.at("format") == expected.at("format") &&
                fixture.at("architecture") == expected.at("architecture_identity") &&
                fixture.at("mode") == expected.at("mode") && fixture.at("endian") == expected.at("endian"),
                "provider fixture identity differs from the materialized corpus");
            const bool required = score.provider == "aida_typed_pipeline" ||
                !managed_only_fixture(expected);
            const auto fixture_status = fixture.at("status").get<std::string>();
            if (!required) {
                require(fixture_status == "not_applicable" && fixture.at("runs").empty(),
                    "native baseline must explicitly mark managed-only fixtures not applicable");
                ++unsupported;
                require(outputs.emplace(id, json()).second,
                    "provider fixture result identifier is duplicated");
                for (std::size_t run_index = 0; run_index < 2; ++run_index) {
                    deterministic_outputs[run_index].push_back(
                        {{"id", id}, {"status", "not_applicable"}});
                    deterministic_source_maps[run_index].push_back(
                        {{"id", id}, {"source_coordinates", json::array()}});
                }
                continue;
            }
            require(fixture_status == "measured" && fixture.at("runs").size() == 2,
                "required provider fixture lacks two measured production runs");
            std::array<std::string, 2> output_hashes;
            std::array<std::string, 2> source_hashes;
            for (std::size_t run_index = 0; run_index < 2; ++run_index) {
                const auto& measured_run = fixture.at("runs")[run_index];
                const auto run_id = require_text(measured_run, "run_id", "provider measured run");
                require(run_ids.insert(run_id).second, "provider run identifier is duplicated");
                const auto started = measured_run.at("started_tick_ns").get<std::uint64_t>();
                const auto ended = measured_run.at("ended_tick_ns").get<std::uint64_t>();
                const auto duration = measured_run.at("duration_ns").get<std::uint64_t>();
                require(ended > started && ended - started == duration,
                    "provider run timing is non-monotonic or self-inconsistent");
                validate_execution_witness(measured_run, "provider measured run");
                const auto& artifacts = measured_run.at("artifacts");
                for (const std::string_view artifact_name : {"provider_ir", "hir", "type_graph",
                         "ast", "document", "printc"}) {
                    const auto& raw = artifacts.at(std::string(artifact_name));
                    if (artifact_required(score.provider, artifact_name)) {
                        const auto artifact_hash = validate_raw_artifact(raw, artifact_name);
                        require(forbidden_artifact_hashes.find(artifact_hash) ==
                                forbidden_artifact_hashes.end(),
                            "raw provider stage copies source, ground-truth, receipt, or target-artifact evidence");
                    } else {
                        require(raw.is_null(), "provider emitted a raw artifact outside its measured contract");
                    }
                }
                json deterministic = {{"outcome", measured_run.at("outcome")},
                    {"artifacts", measured_run.at("artifacts")}, {"facts", measured_run.at("facts")},
                    {"confidence", measured_run.at("confidence")},
                    {"explicit_unknowns", measured_run.at("explicit_unknowns")},
                    {"readability", measured_run.at("readability")},
                    {"diagnostics", measured_run.at("diagnostics")}};
                const auto output_hash = canonical_json_sha256(deterministic);
                require(output_hash.ok, output_hash.error);
                output_hashes[run_index] = output_hash.sha256;
                const auto source_hash = canonical_json_sha256(
                    measured_run.at("facts").at("source_coordinates"));
                require(source_hash.ok, source_hash.error);
                source_hashes[run_index] = source_hash.sha256;
                deterministic_outputs[run_index].push_back(
                    {{"id", id}, {"output_sha256", output_hash.sha256}});
                deterministic_source_maps[run_index].push_back(
                    {{"id", id}, {"source_coordinates_sha256", source_hash.sha256}});
            }
            require(fixture.at("runs")[0].at("run_id") != fixture.at("runs")[1].at("run_id") &&
                fixture.at("runs")[0].at("execution_witness_sha256") !=
                    fixture.at("runs")[1].at("execution_witness_sha256") &&
                fixture.at("runs")[0].at("started_tick_ns") != fixture.at("runs")[1].at("started_tick_ns"),
                "determinism runs do not contain distinct execution witnesses");
            require(output_hashes[0] == output_hashes[1] && source_hashes[0] == source_hashes[1],
                "provider output is nondeterministic across cache-bypassed runs");
            require(outputs.emplace(id, fixture.at("runs")[0]).second,
                "provider fixture result identifier is duplicated");
        }
        for (const auto& id : selected_ids)
            require(outputs.find(id) != outputs.end(), "provider omitted selected fixture: " + id);
        json metrics = json::object();
        for (const auto metric : k_metrics) {
            std::set<std::string, std::less<>> expected;
            std::set<std::string, std::less<>> observed;
            std::set<std::string, std::less<>> unknowns;
            json confidence = json::object();
            for (const auto& id : selected_ids) {
                const auto& expected_record = truth.at(id);
                const auto& output = outputs.at(id);
                for (const auto& fact : metric_facts(expected_record.at("facts"), metric))
                    expected.insert(id + "\n" + fact);
                if (output.is_null())
                    continue;
                for (const auto& fact : metric_facts(output.at("facts"), metric)) {
                    const auto scoped = id + "\n" + fact;
                    observed.insert(scoped);
                    const auto found = output.at("confidence").find(fact);
                    require(found != output.at("confidence").end(), "provider confidence lacks fact: " + fact);
                    confidence[scoped] = *found;
                }
                for (const auto& unknown : strings(output.at("explicit_unknowns"), "explicit_unknowns"))
                    unknowns.insert(id + "\n" + unknown);
            }
            metrics[std::string(metric)] = score_metric(expected, observed,
                score.provider + ":" + std::string(metric), confidence, unknowns);
        }
        std::uint64_t declarations = 0;
        std::uint64_t maximum_expression_depth = 0;
        std::uint64_t maximum_control_nesting = 0;
        std::uint64_t placeholders = 0;
        std::uint64_t casts = 0;
        std::uint64_t fabricated = 0;
        std::uint64_t symbol_count = 0;
        std::uint64_t named_symbols = 0;
        std::uint64_t success = 0;
        json diagnostics = json::array();
        for (const auto& pair : outputs) {
            if (pair.second.is_null())
                continue;
            const auto& readability = pair.second.at("readability");
            require_closed(readability, {"declaration_count", "max_expression_depth", "max_control_nesting",
                "dead_placeholder_count", "cast_count", "fabricated_body_count", "symbol_count", "named_symbol_count"},
                "provider readability");
            for (const auto field : {"declaration_count", "max_expression_depth", "max_control_nesting",
                     "dead_placeholder_count", "cast_count", "fabricated_body_count", "symbol_count", "named_symbol_count"})
                require(readability.contains(field) && readability.at(field).is_number_unsigned(),
                    std::string("provider readability requires unsigned ") + field);
            add_count(declarations, readability.at("declaration_count").get<std::uint64_t>(), "declaration");
            maximum_expression_depth = std::max(maximum_expression_depth,
                readability.at("max_expression_depth").get<std::uint64_t>());
            maximum_control_nesting = std::max(maximum_control_nesting,
                readability.at("max_control_nesting").get<std::uint64_t>());
            add_count(placeholders, readability.at("dead_placeholder_count").get<std::uint64_t>(), "placeholder");
            add_count(casts, readability.at("cast_count").get<std::uint64_t>(), "cast");
            const auto fabricated_bodies = readability.at("fabricated_body_count").get<std::uint64_t>();
            require(fabricated_bodies == 0, "provider returned a fabricated pseudocode body");
            add_count(fabricated, fabricated_bodies, "fabricated body");
            const auto fixture_symbols = readability.at("symbol_count").get<std::uint64_t>();
            const auto fixture_named_symbols = readability.at("named_symbol_count").get<std::uint64_t>();
            require(fixture_named_symbols <= fixture_symbols, "named symbol count exceeds fixture symbol count");
            add_count(symbol_count, fixture_symbols, "symbol");
            add_count(named_symbols, fixture_named_symbols, "named symbol");
            for (const auto& diagnostic : pair.second.at("diagnostics"))
                diagnostics.push_back(diagnostic);
            ++success;
        }
        score.metrics = std::move(metrics);
        score.readability = {{"declaration_count", declarations},
            {"naming_consistency_ratio", symbol_count == 0 ? 1.0 : static_cast<double>(named_symbols) / symbol_count},
            {"max_expression_depth", maximum_expression_depth}, {"max_control_nesting", maximum_control_nesting},
            {"dead_placeholder_count", placeholders}, {"cast_count", casts}, {"fabricated_body_count", fabricated}};
        score.diagnostics = {{"summary", {{"provider_crash", 0}, {"timeout", 0}, {"unsupported", unsupported},
                {"cancelled", 0}, {"success", success}}}, {"events", std::move(diagnostics)}};
        require(provider.contains("cancellation") && provider.at("cancellation").is_object(),
            "provider cancellation evidence is absent");
        const auto& cancellation = provider.at("cancellation");
        require(cancellation.at("status") == "measured" &&
            cancellation.at("outcome") == "cancelled",
            "provider cancellation was not actually observed");
        const auto cancellation_started = cancellation.at("started_tick_ns").get<std::uint64_t>();
        const auto cancellation_requested = cancellation.at("cancel_requested_tick_ns").get<std::uint64_t>();
        const auto cancellation_ended = cancellation.at("ended_tick_ns").get<std::uint64_t>();
        const auto cancellation_latency = cancellation.at("latency_ns").get<std::uint64_t>();
        require(cancellation_started <= cancellation_requested &&
            cancellation_requested <= cancellation_ended &&
            cancellation_ended - cancellation_requested == cancellation_latency &&
            cancellation_latency <= 250ULL * 1000ULL * 1000ULL,
            "provider cancellation timing is non-monotonic, self-inconsistent, or above 250 ms");
        validate_execution_witness(cancellation, "provider cancellation");
        score.cancellation = {{"requested", true}, {"completed_jobs", 0},
            {"cancelled_jobs", 1},
            {"p95_ms", static_cast<double>(cancellation_latency) / 1'000'000.0}};
        score.diagnostics["cancellation"] = score.cancellation;
        score.determinism_runs = json::array();
        for (std::size_t run_index = 0; run_index < 2; ++run_index) {
            const auto output_hash = canonical_json_sha256(deterministic_outputs[run_index]);
            const auto source_hash = canonical_json_sha256(deterministic_source_maps[run_index]);
            require(output_hash.ok && source_hash.ok,
                output_hash.ok ? source_hash.error : output_hash.error);
            score.determinism_runs.push_back({{"run_id", score.provider + "-run-" +
                    std::to_string(run_index + 1U)},
                {"schedule", "bounded_provider_matrix"}, {"cache_state", "cache_bypass"},
                {"normalized_ast_sha256", output_hash.sha256},
                {"source_map_sha256", source_hash.sha256}, {"outcome", "success"}});
        }
        score.normalized_outputs = json::object();
        for (const auto& pair : outputs)
            score.normalized_outputs[pair.first] = pair.second.is_null() ? json() : pair.second.at("facts");
        std::set<std::string, std::less<>> launch_hashes;
        std::set<std::string, std::less<>> artifact_hashes;
        for (const auto& pair : materialized)
            artifact_hashes.insert(pair.second.at("artifact_sha256").get<std::string>());
        for (const auto& launch : provider.at("launch_audit")) {
            const auto hash = launch.at("image_sha256").get<std::string>();
            require(artifact_hashes.find(hash) == artifact_hashes.end(),
                "provider launch audit contains an analyzed artifact");
            require(std::any_of(identity_workers.begin(), identity_workers.end(),
                [&hash](const auto& worker) { return worker.second.first == hash; }),
                "provider launch audit contains an identity-unbound executable");
            require(launch_hashes.insert(hash).second,
                "provider launch audit contains a duplicate executable");
        }
        for (const auto& worker : identity_workers)
            require(launch_hashes.find(worker.second.first) != launch_hashes.end(),
                "provider worker identity lacks an observed launch audit row");
        return score;
    }

    double f1(const provider_score_t& score, std::string_view metric)
    {
        return score.metrics.at(std::string(metric)).at("f1").get<double>();
    }
}

decompiler_quality_score_result_t score_decompiler_quality(
    const decompiler_quality_score_request_t& request)
{
    try {
        require(!request.authorization_id.empty() && !request.receipt_id.empty() && !request.run_id.empty() &&
            !request.started_utc.empty() && !request.ended_utc.empty() && !request.candidate_provider.empty() &&
            !request.harness_binding_id.empty() && !request.scorer_binding_id.empty() &&
            !request.corpus_manifest_binding_id.empty() && !request.recipes_binding_id.empty() &&
            !request.ground_truth_binding_id.empty() && !request.materialization_receipt_binding_id.empty(),
            "quality scoring request identity is incomplete");
        const auto corpus_validation = validate_corpus_manifest(request.corpus_manifest);
        require(corpus_validation.valid, corpus_validation.summary());
        require(request.ground_truth.is_object() && request.ground_truth.value("schema", std::string{}) ==
            "aida.c03.corpus-ground-truth" && request.ground_truth.value("target_execution_forbidden", false),
            "quality ground truth is invalid or permits target execution");
        require(request.materialization_receipt.is_object() &&
            request.materialization_receipt.value("target_execution_forbidden", false),
            "quality materialization evidence is absent or permits target execution");
        const auto bindings = bind_files(request);
        const auto& harness_binding = binding(bindings, request.harness_binding_id);
        const auto& scorer_binding = binding(bindings, request.scorer_binding_id);
        const auto& manifest_binding = binding(bindings, request.corpus_manifest_binding_id);
        const auto& recipes_binding = binding(bindings, request.recipes_binding_id);
        const auto& ground_truth_binding = binding(bindings, request.ground_truth_binding_id);
        const auto& materialization_binding = binding(bindings, request.materialization_receipt_binding_id);
        require(harness_binding.request.kind == "harness_build" && scorer_binding.request.kind == "scorer_build" &&
            manifest_binding.request.kind == "corpus_manifest" && recipes_binding.request.kind == "corpus_recipes" &&
            ground_truth_binding.request.kind == "corpus_ground_truth" &&
            materialization_binding.request.kind == "materialization_receipt",
            "quality core evidence binding kind mismatch");
        require(load_bound_json(request.evidence_root, manifest_binding) == request.corpus_manifest,
            "loaded corpus manifest differs from its evidence binding");
        require(load_bound_json(request.evidence_root, recipes_binding) == request.recipes,
            "loaded corpus recipes differ from their evidence binding");
        require(load_bound_json(request.evidence_root, ground_truth_binding) == request.ground_truth,
            "loaded ground truth differs from its evidence binding");
        require(load_bound_json(request.evidence_root, materialization_binding) == request.materialization_receipt,
            "loaded materialization receipt differs from its evidence binding");
        const auto materialization_validation = validate_materialization_receipt(request.materialization_receipt,
            request.corpus_manifest, request.recipes, request.ground_truth, request.evidence_root / "artifacts");
        require(materialization_validation.valid, materialization_validation.summary());
        const auto truth = index_by_id(normalized_ground_truth_records(request.ground_truth), "ground truth");
        std::map<std::string, json, std::less<>> materialized;
        std::set<std::string, std::less<>> selected_ids;
        json corpus_rows = json::array();
        for (const auto& fixture : request.materialization_receipt.at("fixtures")) {
            const auto id = require_text(fixture, "id", "materialization fixture");
            require(truth.find(id) != truth.end(), "materialized fixture lacks ground truth");
            require(materialized.emplace(id, fixture).second, "materialization fixture is duplicated");
            selected_ids.insert(id);
            const auto artifact_binding_id = "artifact:" + id;
            const auto& artifact_binding = binding(bindings, artifact_binding_id);
            require(artifact_binding.request.kind == "materialized_artifact", "artifact evidence binding kind mismatch");
            require(artifact_binding.sha256 == fixture.at("artifact_sha256").get<std::string>(),
                "materialized artifact hash differs from evidence binding");
            const auto source_binding_id = "source:" + id;
            const auto& source_binding = binding(bindings, source_binding_id);
            require(source_binding.request.kind == "source_ground_truth", "source evidence binding kind mismatch");
            const auto source_path = truth.at(id).at("source").get<std::string>();
            require(request.ground_truth.at("source_files").at(source_path) == source_binding.sha256,
                "source evidence binding differs from the ground-truth source hash inventory");
            const auto truth_hash = canonical_json_sha256(truth.at(id).at("facts"));
            require(truth_hash.ok, truth_hash.error);
            corpus_rows.push_back({{"id", id}, {"artifact_sha256", artifact_binding.sha256},
                {"source_provenance_sha256", source_binding.sha256}, {"semantic_facts_sha256", truth_hash.sha256},
                {"artifact_binding_id", artifact_binding_id}, {"source_binding_id", source_binding_id},
                {"format", truth.at(id).at("format")}, {"architecture", truth.at(id).at("architecture_identity")},
                {"mode", truth.at(id).at("mode")}, {"endian", truth.at(id).at("endian")}});
        }
        require(selected_ids.size() == truth.size(), "quality corpus selection does not cover every ground-truth fixture");
        const auto provider_fixture_set_hash = canonical_json_sha256(
            request.materialization_receipt.at("fixtures"));
        require(provider_fixture_set_hash.ok, provider_fixture_set_hash.error);
        require(request.provider_runs.is_array() && request.provider_runs.size() == 3,
            "quality scoring requires candidate, Ghidra PrintC, and current AiDA provider runs");
        std::map<std::string, provider_score_t, std::less<>> provider_scores;
        for (const auto& provider : request.provider_runs) {
            auto score = score_provider(provider, bindings, request.evidence_root, truth,
                materialized, selected_ids, manifest_binding.sha256, recipes_binding.sha256,
                ground_truth_binding.sha256,
                request.materialization_receipt.at("receipt_sha256").get<std::string>(),
                provider_fixture_set_hash.sha256);
            require(provider_scores.emplace(score.provider, std::move(score)).second,
                "provider quality run is duplicated");
        }
        const auto candidate = provider_scores.find(request.candidate_provider);
        const auto printc = provider_scores.find("ghidra_printc");
        const auto current = provider_scores.find("aida_current");
        require(candidate != provider_scores.end() && printc != provider_scores.end() && current != provider_scores.end(),
            "required quality provider run is absent");
        require(candidate->second.identity.at("protocol_sha256") ==
                printc->second.identity.at("protocol_sha256") &&
            candidate->second.identity.at("protocol_sha256") ==
                current->second.identity.at("protocol_sha256"),
            "quality providers do not bind the same production protocol identity");
        json file_bindings = json::array();
        for (const auto& pair : bindings)
            file_bindings.push_back({{"id", pair.first}, {"kind", pair.second.request.kind},
                {"path", pair.second.request.relative_path}, {"sha256", pair.second.sha256},
                {"max_bytes", pair.second.request.maximum_bytes}});
        json provider_builds = json::array();
        for (const auto& pair : provider_scores) {
            json workers = json::array();
            for (const auto& worker_binding : pair.second.worker_bindings) {
                const auto role = worker_binding.at("role").get<std::string>();
                const auto identity = std::find_if(pair.second.identity.at("workers").begin(),
                    pair.second.identity.at("workers").end(), [&role](const json& worker) {
                        return worker.at("role").get<std::string>() == role;
                    });
                require(identity != pair.second.identity.at("workers").end(),
                    "provider receipt worker binding lacks an identity");
                workers.push_back({{"role", role},
                    {"binary_sha256", identity->at("binary_sha256")},
                    {"manifest_sha256", identity->at("manifest_sha256")},
                    {"binary_binding_id", worker_binding.at("binary_binding_id")},
                    {"manifest_binding_id", worker_binding.at("manifest_binding_id")}});
            }
            provider_builds.push_back({{"provider", pair.first},
                {"build_sha256", pair.second.build_hash},
                {"build_binding_id", pair.second.build_binding_id},
                {"workers", std::move(workers)},
                {"runtime_manifest_sha256", pair.second.identity.at("runtime_manifest_sha256")},
                {"runtime_manifest_binding_id", pair.second.runtime_manifest_binding_id},
                {"spec_manifest_sha256", pair.second.identity.at("spec_manifest_sha256")},
                {"spec_manifest_binding_id", pair.second.spec_manifest_binding_id},
                {"protocol_sha256", pair.second.identity.at("protocol_sha256")},
                {"result_sha256", pair.second.result_hash},
                {"result_binding_id", pair.second.result_binding_id}});
        }
        const auto fixture_set_hash = canonical_json_sha256(corpus_rows);
        require(fixture_set_hash.ok, fixture_set_hash.error);
        json required_formats = request.corpus_manifest.at("required_coverage").at("formats");
        json required_architectures = request.corpus_manifest.at("required_coverage").at("architectures");
        json matrix_rows = json::array();
        for (const auto& row : corpus_rows)
            matrix_rows.push_back({{"fixture_id", row.at("id")}, {"format", row.at("format")},
                {"architecture", row.at("architecture")}, {"mode", row.at("mode")}, {"endian", row.at("endian")}});
        json baseline = json::object();
        for (const auto& pair : std::array<std::pair<std::string_view, const provider_score_t*>, 2>{
                 std::pair<std::string_view, const provider_score_t*>{"ghidra_printc", &printc->second},
                 {"aida_current", &current->second}}) {
            json deltas = json::object();
            for (const auto metric : k_metrics) {
                const double baseline_value = f1(*pair.second, metric);
                const double current_value = f1(candidate->second, metric);
                deltas[std::string(metric)] = {{"baseline_f1", baseline_value}, {"current_f1", current_value},
                    {"delta", current_value - baseline_value}};
            }
            baseline[std::string(pair.first)] = {{"provider", std::string(pair.first)},
                {"provider_build_sha256", pair.second->build_hash}, {"same_fixture_set", true},
                {"fixture_set_sha256", fixture_set_hash.sha256}, {"metric_deltas", std::move(deltas)}};
        }
        json claims = json::array();
        for (const auto metric : k_metrics) {
            claims.push_back({{"id", "objective-" + std::string(metric)}, {"metric_id", std::string(metric)},
                {"actual", f1(candidate->second, metric)},
                {"threshold", decompiler_quality_thresholds().at("metric_f1_min").at(std::string(metric))},
                {"comparator", "gte"},
                {"evidence_ids", json::array({request.candidate_provider + ":" + std::string(metric)})}});
        }
        json receipt = {{"schema", "aida.c03.decompiler-quality-receipt"}, {"schema_version", 2},
            {"receipt_id", request.receipt_id},
            {"provenance", {{"authorization_id", request.authorization_id},
                {"harness_build_sha256", harness_binding.sha256}, {"scorer_build_sha256", scorer_binding.sha256},
                {"corpus_manifest_sha256", manifest_binding.sha256}, {"recipes_sha256", recipes_binding.sha256},
                {"ground_truth_sha256", ground_truth_binding.sha256},
                {"materialization_receipt_sha256", materialization_binding.sha256},
                {"harness_binding_id", request.harness_binding_id}, {"scorer_binding_id", request.scorer_binding_id},
                {"corpus_manifest_binding_id", request.corpus_manifest_binding_id},
                {"recipes_binding_id", request.recipes_binding_id},
                {"ground_truth_binding_id", request.ground_truth_binding_id},
                {"materialization_receipt_binding_id", request.materialization_receipt_binding_id},
                {"evidence_bindings", std::move(file_bindings)}, {"provider_builds", std::move(provider_builds)}}},
            {"corpus", {{"manifest_sha256", manifest_binding.sha256}, {"fixture_set_sha256", fixture_set_hash.sha256},
                {"fixtures", std::move(corpus_rows)}}},
            {"matrix", {{"required_formats", required_formats}, {"observed_formats", required_formats},
                {"required_architectures", required_architectures}, {"observed_architectures", required_architectures},
                {"fixture_matrix", std::move(matrix_rows)}}},
            {"execution", {{"run_id", request.run_id}, {"started_utc", request.started_utc},
                {"ended_utc", request.ended_utc}, {"schedule", "bounded_provider_matrix"},
                {"cache_state", "explicit_disclosed"}, {"target_execution_forbidden", true}}},
            {"metrics", candidate->second.metrics}, {"readability", candidate->second.readability},
            {"determinism", {{"canonicalization_version", "typed-pseudocode-ast-v2"},
                {"runs", candidate->second.determinism_runs}}}, {"baseline", std::move(baseline)},
            {"thresholds", decompiler_quality_thresholds()}, {"diagnostics", candidate->second.diagnostics},
            {"failures", json::array()}, {"claims", std::move(claims)}, {"receipt_sha256", ""}};
        const auto receipt_hash = canonical_json_sha256(receipt, "receipt_sha256");
        require(receipt_hash.ok, receipt_hash.error);
        receipt["receipt_sha256"] = receipt_hash.sha256;
        auto validation = validate_decompiler_quality_receipt_files(receipt, request.evidence_root);
        decompiler_quality_score_result_t output;
        output.ok = validation.valid;
        output.error = validation.valid ? std::string{} : validation.summary();
        output.receipt = std::move(receipt);
        output.validation = std::move(validation);
        return output;
    } catch (const std::exception& error) {
        decompiler_quality_score_result_t output;
        output.error = error.what();
        output.validation.reject("", "scorer_failure", error.what());
        return output;
    }
}
}
