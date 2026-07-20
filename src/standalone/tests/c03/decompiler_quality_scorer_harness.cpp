#include "decompiler_quality_scorer_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "decompiler_quality_scorer.hpp"
#include "evidence_hash.hpp"
#include "fixture_materializer.hpp"

#include <nlohmann/json.hpp>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <ctime>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <tuple>

namespace aida::analysis::c03
{
namespace
{
    json load_json(const std::filesystem::path& path, std::uint64_t maximum)
    {
        std::error_code error;
        const auto size = std::filesystem::file_size(path, error);
        if (error || size == 0 || size > maximum)
            throw std::runtime_error("quality harness JSON file is absent, empty, or oversized");
        std::ifstream stream(path, std::ios::binary);
        if (!stream)
            throw std::runtime_error("quality harness JSON file cannot be opened");
        std::string bytes(static_cast<std::size_t>(size), '\0');
        stream.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        if (!stream || stream.gcount() != static_cast<std::streamsize>(bytes.size()))
            throw std::runtime_error("quality harness JSON file could not be read completely");
        try {
            return json::parse(bytes, nullptr, true, false);
        } catch (const std::exception& parse_error) {
            throw std::runtime_error(std::string("quality harness JSON is malformed: ") +
                parse_error.what());
        }
    }

    std::string load_bytes(const std::filesystem::path& path, std::uint64_t maximum)
    {
        std::error_code error;
        const auto size = std::filesystem::file_size(path, error);
        if (error || size == 0 || size > maximum ||
            size > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()))
            throw std::runtime_error("quality harness binary evidence is absent, empty, or oversized");
        std::ifstream stream(path, std::ios::binary);
        if (!stream)
            throw std::runtime_error("quality harness binary evidence cannot be opened");
        std::string bytes(static_cast<std::size_t>(size), '\0');
        stream.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        if (!stream || stream.gcount() != static_cast<std::streamsize>(bytes.size()))
            throw std::runtime_error("quality harness binary evidence could not be read completely");
        return bytes;
    }

    std::string hex_encode(std::string_view bytes)
    {
        static constexpr std::array<char, 16> digits{
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        if (bytes.size() > (std::numeric_limits<std::size_t>::max)() / 2U)
            throw std::runtime_error("quality harness evidence cannot be hex encoded safely");
        std::string output(bytes.size() * 2U, '\0');
        for (std::size_t index = 0; index < bytes.size(); ++index) {
            const auto value = static_cast<unsigned char>(bytes[index]);
            output[index * 2U] = digits[value >> 4U];
            output[index * 2U + 1U] = digits[value & 0x0fU];
        }
        return output;
    }

    json raw_file_artifact(const std::filesystem::path& path)
    {
        const auto bytes = load_bytes(path, 4ULL * 1024ULL * 1024ULL);
        const auto hash = sha256_evidence_bytes(bytes.data(), bytes.size());
        if (!hash.ok)
            throw std::runtime_error(hash.error);
        return json{{"encoding", "hex"}, {"sha256", hash.sha256},
            {"byte_size", static_cast<std::uint64_t>(bytes.size())},
            {"payload", hex_encode(bytes)}};
    }

    void refresh_execution_witness(json& value)
    {
        value["execution_witness_sha256"] = "";
        const auto hash = canonical_json_sha256(value, "execution_witness_sha256");
        if (!hash.ok)
            throw std::runtime_error(hash.error);
        value["execution_witness_sha256"] = hash.sha256;
    }

    std::string utc_now()
    {
        const auto now = std::chrono::system_clock::now();
        const auto value = std::chrono::system_clock::to_time_t(now);
        std::tm utc{};
        if (gmtime_s(&utc, &value) != 0)
            throw std::runtime_error("quality harness cannot capture UTC time");
        std::ostringstream stream;
        stream << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
        if (!stream)
            throw std::runtime_error("quality harness cannot format UTC time");
        return stream.str();
    }

void require(bool condition, std::string message)
{
	aida::analysis::c03_test::assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
            throw std::runtime_error(std::move(message));
    }

    void copy_bounded(const std::filesystem::path& source, const std::filesystem::path& destination,
        std::uint64_t maximum)
    {
        const auto hash = sha256_evidence_file(source, maximum);
        require(hash.ok, hash.error);
        std::filesystem::create_directories(destination.parent_path());
        auto temporary = destination;
        temporary += L".tmp";
        std::error_code error;
        std::filesystem::remove(temporary, error);
        require(CopyFileW(source.c_str(), temporary.c_str(), FALSE) != FALSE,
            "quality evidence temporary copy failed");
        if (!MoveFileExW(temporary.c_str(), destination.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            const auto win32_error = GetLastError();
            std::filesystem::remove(temporary, error);
            throw std::runtime_error("quality evidence publication failed with Win32 error " +
                std::to_string(win32_error));
        }
        const auto copied = sha256_evidence_file(destination, maximum);
        require(copied.ok && copied.sha256 == hash.sha256,
            copied.ok ? "quality evidence copy hash mismatch" : copied.error);
    }

    quality_file_binding_request_t stage_binding(const std::filesystem::path& evidence_root,
        std::string id, std::string kind, const std::filesystem::path& source,
        std::string relative, std::uint64_t maximum)
    {
        copy_bounded(source, evidence_root / std::filesystem::u8path(relative), maximum);
        const auto hash = sha256_evidence_file(evidence_root / std::filesystem::u8path(relative), maximum);
        require(hash.ok, hash.error);
        return {std::move(id), std::move(kind), std::move(relative), hash.sha256, maximum};
    }

    void write_json_atomic(const std::filesystem::path& path, const json& value)
    {
        std::filesystem::create_directories(path.parent_path());
        auto temporary = path;
        temporary += L".tmp";
        {
            std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
            require(static_cast<bool>(stream), "quality evidence receipt cannot be created");
            const auto text = value.dump();
            stream.write(text.data(), static_cast<std::streamsize>(text.size()));
            stream.flush();
            require(static_cast<bool>(stream), "quality evidence receipt write failed");
        }
        std::error_code error;
        if (!MoveFileExW(temporary.c_str(), path.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            const auto win32_error = GetLastError();
            std::filesystem::remove(temporary, error);
            throw std::runtime_error("quality evidence receipt publication failed with Win32 error " +
                std::to_string(win32_error));
        }
    }

    quality_file_binding_request_t existing_binding(const std::filesystem::path& evidence_root,
        std::string id, std::string kind, std::string relative, std::uint64_t maximum)
    {
        const auto hash = sha256_evidence_file(evidence_root / std::filesystem::u8path(relative), maximum);
        require(hash.ok, hash.error);
        return {std::move(id), std::move(kind), std::move(relative), hash.sha256, maximum};
    }

    json provider_run_from_results(const std::filesystem::path& path,
        std::string_view expected_provider, std::string result_binding)
    {
        const auto evidence = load_json(path, 128ULL * 1024ULL * 1024ULL);
        const auto validation = validate_decompiler_provider_results(evidence);
        require(validation.valid, validation.summary());
        json run = evidence.at("provider_run");
        require(run.value("provider", std::string{}) == expected_provider,
            "decompiler provider result identity is incorrect");
        run["build_binding_id"] = "provider-matrix";
        run["result_binding_id"] = std::move(result_binding);
        run["runtime_manifest_binding_id"] = "managed-runtime-manifest";
        run["spec_manifest_binding_id"] = "ghidra-spec-manifest";
        run["worker_bindings"] = json::array();
        for (const auto& worker : run.at("identity").at("workers")) {
            const auto role = worker.at("role").get<std::string>();
            require(role == "native" || role == "managed",
                "provider result contains an unsupported worker role");
            run["worker_bindings"].push_back({{"role", role},
                {"binary_binding_id", role + "-worker-binary"},
                {"manifest_binding_id", role + "-worker-manifest"}});
        }
        return run;
    }

    decompiler_quality_score_request_t rebind_provider_result(
        const decompiler_quality_score_request_t& source, std::size_t provider_index,
        json evidence, std::string relative_path)
    {
        require(provider_index < source.provider_runs.size(),
            "adverse provider index is outside the scorer request");
        auto request = source;
        const auto result_binding_id = request.provider_runs[provider_index]
            .at("result_binding_id").get<std::string>();
        write_json_atomic(request.evidence_root /
            std::filesystem::u8path(relative_path), evidence);
        const auto hash = sha256_evidence_file(request.evidence_root /
            std::filesystem::u8path(relative_path), 128ULL * 1024ULL * 1024ULL);
        require(hash.ok, hash.error);
        const auto binding = std::find_if(request.file_bindings.begin(),
            request.file_bindings.end(), [&result_binding_id](const auto& current) {
                return current.id == result_binding_id;
            });
        require(binding != request.file_bindings.end(),
            "adverse provider result binding is absent");
        binding->relative_path = std::move(relative_path);
        binding->expected_sha256 = hash.sha256;
        json rebound = evidence.at("provider_run");
        for (const auto field : {"build_binding_id", "result_binding_id", "worker_bindings",
                 "runtime_manifest_binding_id", "spec_manifest_binding_id"})
            rebound[field] = request.provider_runs[provider_index].at(field);
        request.provider_runs[provider_index] = std::move(rebound);
        return request;
    }
}

bool run_decompiler_quality_scorer_harness(const quality_harness_paths_t& paths,
    std::string& failure)
{
    try {
        const auto fixture_root = paths.repository_root / "src/standalone/tests/c03/fixtures";
        const auto manifest = load_json(fixture_root / "corpus_manifest.json", 4ULL * 1024ULL * 1024ULL);
        const auto recipes = load_json(fixture_root / "corpus_generator_recipes.json", 4ULL * 1024ULL * 1024ULL);
        const auto truth = load_json(fixture_root / "corpus_ground_truth.json", 8ULL * 1024ULL * 1024ULL);
        std::filesystem::create_directories(paths.evidence_root);
        const auto materialized = materialize_c03_corpus(manifest, recipes, truth,
            paths.evidence_root / "artifacts");
        require(materialized.ok, materialized.error);
        decompiler_quality_score_request_t request;
        request.evidence_root = paths.evidence_root;
        request.authorization_id = "c03-safe-headless-quality-authorized";
        request.receipt_id = "c03-source-known-quality";
        request.started_utc = utc_now();
        request.candidate_provider = "aida_typed_pipeline";
        request.harness_binding_id = "quality-harness";
        request.scorer_binding_id = "quality-scorer";
        request.corpus_manifest_binding_id = "corpus-manifest";
        request.recipes_binding_id = "corpus-recipes";
        request.ground_truth_binding_id = "corpus-ground-truth";
        request.materialization_receipt_binding_id = "materialization-receipt";
        request.file_bindings.push_back(stage_binding(paths.evidence_root, "quality-harness", "harness_build",
            paths.harness_binary, "bindings/quality_harness.exe", 256ULL * 1024ULL * 1024ULL));
        request.file_bindings.push_back(stage_binding(paths.evidence_root, "quality-scorer", "scorer_build",
            paths.harness_binary, "bindings/quality_scorer.exe", 256ULL * 1024ULL * 1024ULL));
        request.file_bindings.push_back(stage_binding(paths.evidence_root, "provider-matrix", "provider_build",
            paths.provider_matrix_binary, "bindings/provider_matrix.exe", 512ULL * 1024ULL * 1024ULL));
        request.file_bindings.push_back(stage_binding(paths.evidence_root, "native-worker-binary", "worker_binary",
            paths.runtime_root / "deps/AiDA_NativeDecompilerWorker.exe",
            "bindings/AiDA_NativeDecompilerWorker.exe", 512ULL * 1024ULL * 1024ULL));
        request.file_bindings.push_back(stage_binding(paths.evidence_root, "native-worker-manifest", "worker_manifest",
            paths.runtime_root / "deps/AiDA_NativeDecompilerWorker.manifest.bin",
            "bindings/AiDA_NativeDecompilerWorker.manifest.bin", 16ULL * 1024ULL * 1024ULL));
        request.file_bindings.push_back(stage_binding(paths.evidence_root, "managed-worker-binary", "worker_binary",
            paths.runtime_root / "deps/AiDA_ManagedDecompilerWorker.exe",
            "bindings/AiDA_ManagedDecompilerWorker.exe", 512ULL * 1024ULL * 1024ULL));
        request.file_bindings.push_back(stage_binding(paths.evidence_root, "managed-worker-manifest", "worker_manifest",
            paths.runtime_root / "deps/AiDA_ManagedDecompilerWorker.manifest.bin",
            "bindings/AiDA_ManagedDecompilerWorker.manifest.bin", 16ULL * 1024ULL * 1024ULL));
        request.file_bindings.push_back(stage_binding(paths.evidence_root, "managed-runtime-manifest", "runtime_manifest",
            paths.runtime_root / "deps/AiDA_ManagedRuntime.manifest.json",
            "bindings/AiDA_ManagedRuntime.manifest.json", 16ULL * 1024ULL * 1024ULL));
        request.file_bindings.push_back(stage_binding(paths.evidence_root, "ghidra-spec-manifest", "spec_manifest",
            paths.runtime_root / "deps/AiDA_GhidraSpecs.manifest.json",
            "bindings/AiDA_GhidraSpecs.manifest.json", 16ULL * 1024ULL * 1024ULL));
        request.file_bindings.push_back(stage_binding(paths.evidence_root, "corpus-manifest", "corpus_manifest",
            fixture_root / "corpus_manifest.json", "bindings/corpus_manifest.json", 4ULL * 1024ULL * 1024ULL));
        request.file_bindings.push_back(stage_binding(paths.evidence_root, "corpus-recipes", "corpus_recipes",
            fixture_root / "corpus_generator_recipes.json", "bindings/corpus_recipes.json", 4ULL * 1024ULL * 1024ULL));
        request.file_bindings.push_back(stage_binding(paths.evidence_root, "corpus-ground-truth", "corpus_ground_truth",
            fixture_root / "corpus_ground_truth.json", "bindings/corpus_ground_truth.json", 8ULL * 1024ULL * 1024ULL));
        write_json_atomic(paths.evidence_root / "bindings/materialization_receipt.json", materialized.receipt);
        request.file_bindings.push_back(existing_binding(paths.evidence_root, "materialization-receipt",
            "materialization_receipt", "bindings/materialization_receipt.json", 16ULL * 1024ULL * 1024ULL));
        const std::array<std::tuple<std::string, std::string, std::filesystem::path>, 3> provider_files{
            std::tuple<std::string, std::string, std::filesystem::path>{
                "candidate", "aida_typed_pipeline", paths.candidate_results},
            {"ghidra-printc", "ghidra_printc", paths.ghidra_printc_results},
            {"aida-current", "aida_current", paths.aida_current_results}};
        json provider_runs = json::array();
        for (const auto& provider : provider_files) {
            const auto& id = std::get<0>(provider);
            request.file_bindings.push_back(stage_binding(paths.evidence_root, "results:" + id, "provider_results",
                std::get<2>(provider), "bindings/" + id + ".results.json", 128ULL * 1024ULL * 1024ULL));
            provider_runs.push_back(provider_run_from_results(paths.evidence_root /
                std::filesystem::u8path("bindings/" + id + ".results.json"),
                std::get<1>(provider), "results:" + id));
        }
        for (const auto& fixture : truth.at("fixtures")) {
            const auto id = fixture.at("id").get<std::string>();
            const auto source = fixture.at("source").get<std::string>();
            const auto source_path = fixture_root / std::filesystem::u8path(source);
            const auto relative = "sources/" + id + source_path.extension().u8string();
            request.file_bindings.push_back(stage_binding(paths.evidence_root, "source:" + id,
                "source_ground_truth", source_path, relative, 4ULL * 1024ULL * 1024ULL));
        }
        for (const auto& artifact : materialized.fixtures) {
            request.file_bindings.push_back({"artifact:" + artifact.id, "materialized_artifact",
                "artifacts/" + artifact.path.filename().u8string(), artifact.artifact_sha256,
                64ULL * 1024ULL * 1024ULL});
        }
        request.corpus_manifest = load_json(paths.evidence_root / "bindings/corpus_manifest.json", 4ULL * 1024ULL * 1024ULL);
        request.recipes = load_json(paths.evidence_root / "bindings/corpus_recipes.json", 4ULL * 1024ULL * 1024ULL);
        request.ground_truth = truth;
        request.materialization_receipt = materialized.receipt;
        request.provider_runs = std::move(provider_runs);
        const auto run_identity = canonical_json_sha256(
            json{{"providers", request.provider_runs},
                 {"started_utc", request.started_utc}});
        require(run_identity.ok, run_identity.error);
        request.run_id = "c03-quality-" + run_identity.sha256.substr(0, 24);
        request.ended_utc = utc_now();
        const auto score = score_decompiler_quality(request);
        require(score.ok, score.error);
        write_json_atomic(paths.evidence_root /
            "decompiler_quality_receipt.json", score.receipt);
        auto stale = request;
        stale.file_bindings.front().relative_path = "bindings/corpus_manifest.json";
        const auto stale_score = score_decompiler_quality(stale);
        require(!stale_score.ok, "stale provider or harness identity was accepted");
        auto duplicate = request;
        duplicate.provider_runs.push_back(duplicate.provider_runs.front());
        require(!score_decompiler_quality(duplicate).ok, "duplicate provider evidence was accepted");
        const auto candidate_evidence = load_json(paths.evidence_root /
            "bindings/candidate.results.json", 128ULL * 1024ULL * 1024ULL);
        auto schema_v1 = candidate_evidence;
        schema_v1["schema_version"] = 1;
        require(!validate_decompiler_provider_results(schema_v1).valid,
            "legacy schema-v1 provider evidence was accepted");
        auto target_execution = candidate_evidence;
        target_execution["target_execution_observed"] = true;
        require(!score_decompiler_quality(rebind_provider_result(request, 0,
            std::move(target_execution), "adverse/target-execution.results.json")).ok,
            "provider evidence admitting target execution was accepted");
        auto nonmeasurement = candidate_evidence;
        nonmeasurement["measurement_eligible"] = false;
        nonmeasurement["provider_run"]["status"] = "not_measured";
        nonmeasurement["provider_run"]["status_reason"] = "adverse_nonmeasurement";
        require(!score_decompiler_quality(rebind_provider_result(request, 0,
            std::move(nonmeasurement), "adverse/nonmeasurement.results.json")).ok,
            "typed nonmeasurement evidence produced a quality receipt");
        const auto measured_fixture = std::find_if(
            candidate_evidence.at("provider_run").at("fixtures").begin(),
            candidate_evidence.at("provider_run").at("fixtures").end(),
            [](const json& fixture) { return fixture.at("status") == "measured"; });
        require(measured_fixture !=
            candidate_evidence.at("provider_run").at("fixtures").end(),
            "candidate evidence contains no measured fixture for adverse validation");
        const auto fixture_index = static_cast<std::size_t>(std::distance(
            candidate_evidence.at("provider_run").at("fixtures").begin(), measured_fixture));
        auto payload_tamper = candidate_evidence;
        auto& document_payload = payload_tamper["provider_run"]["fixtures"][fixture_index]
            ["runs"][0]["artifacts"]["document"]["payload"].get_ref<std::string&>();
        require(!document_payload.empty(), "candidate document payload is empty");
        document_payload.back() = document_payload.back() == '0' ? '1' : '0';
        require(!score_decompiler_quality(rebind_provider_result(request, 0,
            std::move(payload_tamper), "adverse/payload-tamper.results.json")).ok,
            "raw provider payload tampering was accepted");
        auto source_copy = candidate_evidence;
        const auto measured_id = measured_fixture->at("id").get<std::string>();
        const auto truth_fixture = std::find_if(truth.at("fixtures").begin(),
            truth.at("fixtures").end(), [&measured_id](const json& fixture) {
                return fixture.at("id") == measured_id;
            });
        require(truth_fixture != truth.at("fixtures").end(),
            "measured fixture lacks a source-ground-truth record");
        auto& copied_run = source_copy["provider_run"]["fixtures"][fixture_index]["runs"][0];
        copied_run["artifacts"]["document"] = raw_file_artifact(fixture_root /
            std::filesystem::u8path(truth_fixture->at("source").get<std::string>()));
        refresh_execution_witness(copied_run);
        require(!score_decompiler_quality(rebind_provider_result(request, 0,
            std::move(source_copy), "adverse/source-copy.results.json")).ok,
            "raw provider stage copied source-ground-truth evidence");
        auto witness_tamper = candidate_evidence;
        const auto false_witness = sha256_evidence_text("c03-adverse-false-witness");
        require(false_witness.ok, false_witness.error);
        witness_tamper["provider_run"]["fixtures"][fixture_index]["runs"][0]
            ["execution_witness_sha256"] = false_witness.sha256;
        require(!score_decompiler_quality(rebind_provider_result(request, 0,
            std::move(witness_tamper), "adverse/witness-tamper.results.json")).ok,
            "forged provider execution witness was accepted");
        auto cancellation_tamper = candidate_evidence;
        cancellation_tamper["provider_run"]["cancellation"]["latency_ns"] =
            cancellation_tamper["provider_run"]["cancellation"]["latency_ns"]
                .get<std::uint64_t>() + 1U;
        require(!score_decompiler_quality(rebind_provider_result(request, 0,
            std::move(cancellation_tamper), "adverse/cancellation-tamper.results.json")).ok,
            "forged provider cancellation timing was accepted");
        auto launch_tamper = candidate_evidence;
        require(!launch_tamper["provider_run"]["launch_audit"].empty(),
            "candidate launch audit is empty");
        const auto foreign_image = sha256_evidence_text("c03-adverse-target-image");
        require(foreign_image.ok, foreign_image.error);
        launch_tamper["provider_run"]["launch_audit"][0]["image_sha256"] =
            foreign_image.sha256;
        require(!score_decompiler_quality(rebind_provider_result(request, 0,
            std::move(launch_tamper), "adverse/unbound-launch.results.json")).ok,
            "identity-unbound provider launch was accepted");
        failure.clear();
        return true;
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        failure = error.what();
        return false;
    }
}
}
