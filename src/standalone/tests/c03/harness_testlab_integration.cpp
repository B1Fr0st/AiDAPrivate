#include "harness_testlab_integration.hpp"

#include "assertion_telemetry/assertion_telemetry_fixtures.hpp"
#include "testlab_runtime/result_adapter.hpp"

#include "../../src/core/testlab/test_lab_features_c03_safe_headless.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace aida::analysis::c03_test {
namespace {

using json = nlohmann::json;
using namespace test_lab::c03_safe_headless;

class handle_t final {
public:
	handle_t() = default;
	explicit handle_t(HANDLE value) noexcept : value_(value) {}
	~handle_t() { if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
	HANDLE get() const noexcept { return value_; }
	explicit operator bool() const noexcept { return value_ && value_ != INVALID_HANDLE_VALUE; }
private:
	HANDLE value_ = nullptr;
};

class fixture_root_t final {
public:
	explicit fixture_root_t(const std::filesystem::path& scratch_root) {
		std::error_code error;
		const auto parent = std::filesystem::absolute(scratch_root, error).lexically_normal();
		if (error)
			throw std::runtime_error("Test Lab scratch root is unavailable");
		std::filesystem::create_directories(parent, error);
		if (error || !std::filesystem::is_directory(parent, error) || error)
			throw std::runtime_error("Test Lab scratch root is unavailable");
		const DWORD parent_attributes = GetFileAttributesW(parent.c_str());
		if (parent_attributes == INVALID_FILE_ATTRIBUTES || (parent_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
			throw std::runtime_error("Test Lab scratch root is a reparse point");
		const auto prefix = L"aida-c03-testlab-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
			std::to_wstring(GetTickCount64()) + L"-";
		for (std::uint32_t attempt = 0; attempt < 64; ++attempt) {
			root_ = parent / (prefix + std::to_wstring(attempt));
			if (std::filesystem::create_directory(root_, error)) break;
			if (error && error != std::errc::file_exists)
				throw std::runtime_error("Test Lab fixture root could not be created");
			error.clear();
			root_.clear();
		}
		if (root_.empty()) throw std::runtime_error("Test Lab fixture root could not be reserved");
	}
	~fixture_root_t() {
		if (root_.empty()) return;
		const DWORD root_attributes = GetFileAttributesW(root_.c_str());
		if (root_attributes == INVALID_FILE_ATTRIBUTES ||
			(root_attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != FILE_ATTRIBUTE_DIRECTORY)
			return;
		std::error_code error;
		for (std::filesystem::directory_iterator iterator(root_,
			std::filesystem::directory_options::skip_permission_denied, error), end; !error && iterator != end;
			iterator.increment(error)) {
			const auto& path = iterator->path();
			const DWORD attributes = GetFileAttributesW(path.c_str());
			if (attributes == INVALID_FILE_ATTRIBUTES ||
				(attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) continue;
			SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);
			DeleteFileW(path.c_str());
		}
		RemoveDirectoryW(root_.c_str());
	}
	const std::filesystem::path& path() const noexcept { return root_; }
private:
	std::filesystem::path root_;
};

void require(bool condition, std::string_view message) {
	assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
	if (!condition) throw std::runtime_error(std::string(message));
}

void registry_probe_run(test_lab::state_t&, test_lab::result_t&) {
}

std::string sha256_file(const std::filesystem::path& path) {
	handle_t file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
	require(static_cast<bool>(file), "fixture file could not be opened for hashing");
	BCRYPT_ALG_HANDLE algorithm = nullptr;
	require(BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0)),
		"fixture SHA-256 provider could not be opened");
	struct algorithm_guard_t {
		BCRYPT_ALG_HANDLE value;
		~algorithm_guard_t() { if (value) BCryptCloseAlgorithmProvider(value, 0); }
	} algorithm_guard{algorithm};
	DWORD object_size = 0;
	DWORD received = 0;
	require(BCRYPT_SUCCESS(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
		reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &received, 0)) &&
		received == sizeof(object_size) && object_size != 0, "fixture SHA-256 object size is invalid");
	std::vector<std::uint8_t> object(object_size);
	BCRYPT_HASH_HANDLE hash = nullptr;
	require(BCRYPT_SUCCESS(BCryptCreateHash(algorithm, &hash, object.data(), object_size, nullptr, 0, 0)),
		"fixture SHA-256 hash could not be created");
	struct hash_guard_t {
		BCRYPT_HASH_HANDLE value;
		~hash_guard_t() { if (value) BCryptDestroyHash(value); }
	} hash_guard{hash};
	std::array<std::uint8_t, 65536> buffer{};
	for (;;) {
		DWORD count = 0;
		require(ReadFile(file.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &count, nullptr) != FALSE,
			"fixture file could not be read for hashing");
		if (count == 0) break;
		require(BCRYPT_SUCCESS(BCryptHashData(hash, buffer.data(), count, 0)),
			"fixture hash data could not be consumed");
	}
	std::array<std::uint8_t, 32> digest{};
	require(BCRYPT_SUCCESS(BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0)),
		"fixture SHA-256 could not be finalized");
	static constexpr char hex[] = "0123456789abcdef";
	std::string output(64, '\0');
	for (std::size_t index = 0; index < digest.size(); ++index) {
		output[index * 2] = hex[digest[index] >> 4];
		output[index * 2 + 1] = hex[digest[index] & 0x0f];
	}
	return output;
}

void write_text(const std::filesystem::path& path, std::string_view bytes) {
	handle_t file(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr));
	require(static_cast<bool>(file), "fixture file could not be created");
	std::size_t offset = 0;
	while (offset < bytes.size()) {
		DWORD written = 0;
		const DWORD requested = static_cast<DWORD>((std::min)(bytes.size() - offset,
			static_cast<std::size_t>(65536)));
		require(WriteFile(file.get(), bytes.data() + offset, requested, &written, nullptr) != FALSE && written != 0,
			"fixture file could not be written");
		offset += written;
	}
	require(FlushFileBuffers(file.get()) != FALSE, "fixture file could not be flushed");
}

json safe_flags() {
	return {
		{"safe_headless", true}, {"requires_driver", false}, {"requires_network", false},
		{"launches_application", false}, {"launches_bootstrap", false}, {"performs_packaging", false},
		{"performs_deployment", false}, {"performs_live_operation", false},
		{"performs_debugger_operation", false}, {"executes_target_artifact", false},
		{"mutates_source_or_repository", false}
	};
}

void validate_testlab_outcome_contract() {
	constexpr std::array<entry_outcome_e, 9> entries{{
		entry_outcome_e::not_run, entry_outcome_e::missing, entry_outcome_e::passed,
		entry_outcome_e::failed, entry_outcome_e::timed_out, entry_outcome_e::crashed,
		entry_outcome_e::cancelled, entry_outcome_e::malformed_result,
		entry_outcome_e::integrity_failure
	}};
	constexpr std::array<test_lab::outcome_e, 9> outcomes{{
		test_lab::outcome_e::not_run, test_lab::outcome_e::missing, test_lab::outcome_e::passed,
		test_lab::outcome_e::failed, test_lab::outcome_e::timed_out, test_lab::outcome_e::crashed,
		test_lab::outcome_e::cancelled, test_lab::outcome_e::malformed_result,
		test_lab::outcome_e::integrity_failure
	}};
	constexpr std::array<std::string_view, 9> names{{
		"not_run", "missing", "passed", "failed", "timed_out", "crashed", "cancelled",
		"malformed_result", "integrity_failure"
	}};
	for (std::size_t index = 0; index < entries.size(); ++index) {
		require(to_testlab_outcome(entries[index]) == outcomes[index] &&
			std::string_view(outcome_name(entries[index])) == names[index],
			"Test Lab outcome mapping is incomplete");
	}
	test_lab::result_t passed;
	passed.ok = true;
	test_lab::normalize_legacy_result(passed);
	require(passed.outcome == test_lab::outcome_e::passed, "legacy pass was not normalized");
	test_lab::result_t failed;
	test_lab::normalize_legacy_result(failed);
	require(failed.outcome == test_lab::outcome_e::failed, "executed legacy default was not normalized to failure");
	test_lab::result_t skipped;
	skipped.skipped = true;
	test_lab::normalize_legacy_result(skipped);
	require(skipped.outcome == test_lab::outcome_e::not_run, "legacy skip was not preserved");
	test_lab::result_t explicit_result;
	explicit_result.outcome = test_lab::outcome_e::timed_out;
	test_lab::normalize_legacy_result(explicit_result);
	require(explicit_result.outcome == test_lab::outcome_e::timed_out, "explicit terminal outcome was overwritten");
	const auto before = test_lab::all_features();
	const test_lab::feature_t probe{"c03-registry-probe", test_lab::driver_e::driverless,
		"C03 Registry Probe", "C03 registry duplicate and append-order probe", nullptr, registry_probe_run};
	require(test_lab::register_feature(probe), "unique Test Lab feature registration failed");
	require(!test_lab::register_feature(probe), "duplicate Test Lab feature registration was accepted");
	const auto& after = test_lab::all_features();
	require(after.size() == before.size() + 1, "Test Lab registry cardinality changed unexpectedly");
	for (std::size_t index = 0; index < before.size(); ++index) {
		require(std::strcmp(after[index].category, before[index].category) == 0 &&
			std::strcmp(after[index].name, before[index].name) == 0,
			"Test Lab registry reordered an existing feature");
	}
}

struct category_fixture_t {
	std::string_view category;
	std::string_view requirement;
	std::string_view mode;
	entry_outcome_e expected;
};

constexpr std::array<category_fixture_t, 22> k_categories{{
	{"authority", "ACT-01", "pass", entry_outcome_e::passed},
	{"contract", "VER-01", "fail", entry_outcome_e::failed},
	{"fixture", "HAR-01", "malformed", entry_outcome_e::malformed_result},
	{"provider", "PERF-01", "crash", entry_outcome_e::crashed},
	{"layout", "PERF-02", "hang", entry_outcome_e::timed_out},
	{"store", "PERF-03", "missing", entry_outcome_e::missing},
	{"scheduler", "PERF-04", "integrity", entry_outcome_e::integrity_failure},
	{"reader", "FMT-01", "memory", entry_outcome_e::passed},
	{"container", "FMT-03", "pass", entry_outcome_e::passed},
	{"decode", "ARCH-01", "pass", entry_outcome_e::passed},
	{"recovery", "REC-01", "pass", entry_outcome_e::passed},
	{"query", "REC-02", "pass", entry_outcome_e::passed},
	{"persistence", "PERF-08", "pass", entry_outcome_e::passed},
	{"decompiler", "DEC-01", "pass", entry_outcome_e::passed},
	{"worker", "DEP-02", "pass", entry_outcome_e::passed},
	{"mcp", "MCP-01", "pass", entry_outcome_e::passed},
	{"workbench", "WB-01", "pass", entry_outcome_e::passed},
	{"performance", "PERF-10", "pass", entry_outcome_e::passed},
	{"package", "DEP-04", "stdout", entry_outcome_e::failed},
	{"surface", "SURF-01", "pass", entry_outcome_e::passed},
	{"message_pump", "SEC-01", "pass", entry_outcome_e::passed},
	{"security", "VER-02", "child", entry_outcome_e::passed}
}};

json materialize_manifest(const fixture_root_t& fixture, const std::filesystem::path& fake_adapter,
	std::string& manifest_hash) {
	std::error_code error;
	const auto source = std::filesystem::absolute(fake_adapter, error).lexically_normal();
	require(!error && std::filesystem::is_regular_file(source, error) && !error,
		"fake Test Lab adapter is unavailable");
	const auto source_hash = sha256_file(source);
	const auto source_size = std::filesystem::file_size(source, error);
	require(!error && source_size != 0, "fake Test Lab adapter size is invalid");
	json root = {
		{"schema", "aida.c03.safe-headless.manifest.v2"}, {"version", 2},
		{"build_identity", source_hash}, {"contract_identity", source_hash}, {"entries", json::array()}
	};
	const auto runtime_fixture = fixture.path() / L"runtime-fixture.bin";
	write_text(runtime_fixture, "c03-safe-headless-runtime-fixture");
	const auto runtime_fixture_hash = sha256_file(runtime_fixture);
	const auto runtime_fixture_size = std::filesystem::file_size(runtime_fixture, error);
	require(!error && runtime_fixture_size != 0, "runtime fixture size is invalid");
	for (std::size_t index = 0; index < k_categories.size(); ++index) {
		const auto& fixture_case = k_categories[index];
		const auto file_name = std::string("fixture-") + std::to_string(index) + ".exe";
		const auto destination = fixture.path() / file_name;
		const bool missing = fixture_case.mode == "missing";
		if (!missing) {
			std::filesystem::copy_file(source, destination, std::filesystem::copy_options::none, error);
			require(!error, "fake Test Lab adapter could not be staged");
		}
		const bool integrity = fixture_case.mode == "integrity";
		const auto executable_hash = (missing || integrity) ? std::string(64, '0') : source_hash;
		const auto executable_size = missing ? 1ULL : source_size;
		const bool quality_entry = fixture_case.category == "decompiler";
		const auto id = quality_entry ? std::string("decompiler.quality_scorer") :
			std::string("fixture.") + std::string(fixture_case.category);
		const auto target = quality_entry ? std::string("aida_c03_a06_decompiler_quality_scorer_harness") :
			std::string("aida_c03_fixture_") + std::string(fixture_case.category);
		const auto source_file = std::string("src/standalone/tests/c03/testlab_runtime/") +
			std::string(fixture_case.category) + "_fixture.cpp";
		json runtime_files = json::array();
		if (index == 0) runtime_files.push_back({
			{"relative_path", "runtime-fixture.bin"}, {"size", runtime_fixture_size},
			{"sha256", runtime_fixture_hash}
		});
		root["entries"].push_back({
			{"id", id}, {"category", std::string(fixture_case.category)},
			{"requirement_ids", json::array({std::string(fixture_case.requirement)})}, {"source_target", target},
			{"source_files", json::array({source_file})}, {"runtime_files", std::move(runtime_files)},
			{"executable_relative_path", file_name},
			{"working_directory_relative_path", "."},
			{"arguments", json::array({std::string("--mode=") + std::string(fixture_case.mode)})},
			{"executable_size", executable_size}, {"executable_sha256", executable_hash},
			{"build_identity", source_hash}, {"max_active_processes", quality_entry ? 4 : 1},
			{"max_wall_ms", quality_entry ? 1800000 : 120000},
			{"max_private_bytes", 64ULL * 1024ULL * 1024ULL}, {"max_stdout_bytes", 65536},
			{"max_stderr_bytes", 65536}, {"max_result_bytes", 65536},
			{"expected_result_schema", "aida.c03.safe-headless.result.v1"}, {"safety", safe_flags()}
		});
	}
	const auto manifest_path = fixture.path() / L"manifest.json";
	write_text(manifest_path, root.dump());
	manifest_hash = sha256_file(manifest_path);
	write_text(fixture.path() / L"manifest.sha256", manifest_hash + "\n");
	return root;
}

void validate_outcome_matrix(const fixture_root_t& fixture, const manifest_load_result_t& loaded) {
	require(loaded.accepted && loaded.manifest.entries.size() == k_categories.size(),
		"valid manifest was rejected or lost category entries");
	for (std::size_t index = 0; index < loaded.manifest.entries.size(); ++index) {
		const auto& entry = loaded.manifest.entries[index];
		const bool quality_entry = entry.id == "decompiler.quality_scorer" &&
			entry.source_target == "aida_c03_a06_decompiler_quality_scorer_harness";
		require(entry.max_active_processes == (quality_entry ? 4U : 1U),
			"manifest active-process contract did not preserve its exact bounded identity");
		require(entry.max_wall_ms == (quality_entry ? 1800000U : 120000U),
			"manifest wall contract did not preserve its exact bounded identity");
		std::uint32_t deadline_polls = 0;
		const deadline_probe_t deadline = k_categories[index].mode == "hang" ?
			deadline_probe_t([&deadline_polls] { return ++deadline_polls >= 4; }) : deadline_probe_t{};
		const auto outcome = execute_entry(fixture.path(), loaded.manifest.entries[index], {}, deadline).outcome;
		require(outcome == k_categories[index].expected, "runner outcome matrix did not preserve an exact terminal state");
	}
	std::uint32_t cancellation_polls = 0;
	const auto cancelled = execute_entry(fixture.path(), loaded.manifest.entries[4],
		[&cancellation_polls] { return ++cancellation_polls >= 4; });
	require(cancelled.outcome == entry_outcome_e::cancelled, "in-flight cancellation was not preserved");
	const auto not_run = execute_manifest(fixture.path(), loaded, [] { return true; });
	require(not_run.not_run == loaded.manifest.entries.size() && not_run.entries.size() == loaded.manifest.entries.size(),
		"suite cancellation did not retain explicit not-run entries");
	auto empty_result_entry = loaded.manifest.entries.front();
	empty_result_entry.arguments = {"--mode=empty"};
	require(execute_entry(fixture.path(), empty_result_entry).outcome == entry_outcome_e::malformed_result,
		"empty result envelope was accepted");
	auto missing_runtime = loaded.manifest.entries.front();
	missing_runtime.runtime_files.front().relative_path = L"missing-runtime.bin";
	require(execute_entry(fixture.path(), missing_runtime).outcome == entry_outcome_e::missing,
		"missing runtime fixture did not preserve its terminal state");
	auto mismatched_runtime = loaded.manifest.entries.front();
	mismatched_runtime.runtime_files.front().sha256.assign(64, '0');
	require(execute_entry(fixture.path(), mismatched_runtime).outcome == entry_outcome_e::integrity_failure,
		"mismatched runtime fixture identity was accepted");
	manifest_load_result_t rejected;
	rejected.error = "synthetic rejected manifest";
	const auto rejected_suite = execute_manifest(fixture.path(), rejected);
	require(rejected_suite.integrity_failure == 1 && rejected_suite.entries.size() == 1,
		"rejected empty manifest aggregated to a false pass");
}

std::string evidence_value(const entry_result_t& result, std::string_view name) {
	for (const auto& field : result.evidence) {
		if (field.name == name) return field.value;
	}
	return {};
}

entry_result_t execute_mode(const fixture_root_t& fixture, const manifest_entry_t& source,
	std::string_view mode) {
	auto entry = source;
	entry.arguments = {std::string("--mode=") + std::string(mode)};
	return execute_entry(fixture.path(), entry);
}

void validate_assertion_result_matrix(const fixture_root_t& fixture,
	const manifest_load_result_t& loaded) {
	const auto& source = loaded.manifest.entries.front();
	const auto multi_pass = execute_mode(fixture, source, "multi_pass");
	require(multi_pass.outcome == entry_outcome_e::passed && multi_pass.assertions.total == 3 &&
		multi_pass.assertions.passed == 3 && multi_pass.assertions.failed == 0,
		"multi-pass adapter did not preserve execution-owned assertion counts");
	for (const auto mode : {"fail_first", "fail_middle", "fail_last"}) {
		const auto failed = execute_mode(fixture, source, mode);
		require(failed.outcome == entry_outcome_e::failed && failed.assertions.total == 3 &&
			failed.assertions.passed == 2 && failed.assertions.failed == 1 &&
			!evidence_value(failed, "first_failure").empty(),
			"positioned assertion failure did not preserve exact counts and failure evidence");
	}
	const auto thrown = execute_mode(fixture, source, "throw_after_passes");
	require(thrown.outcome == entry_outcome_e::failed && thrown.assertions.total == 3 &&
		thrown.assertions.passed == 2 && thrown.assertions.failed == 1,
		"exception after passing assertions did not produce an execution-owned failure event");
	const auto not_run = execute_mode(fixture, source, "not_run");
	require(not_run.outcome == entry_outcome_e::not_run && not_run.assertions.not_run &&
		not_run.assertions.total == 0 && not_run.assertions.skipped == 1,
		"explicit adapter not-run result was not preserved");
	const auto threaded_first = execute_mode(fixture, source, "threaded");
	const auto threaded_second = execute_mode(fixture, source, "threaded");
	require(threaded_first.outcome == entry_outcome_e::passed && threaded_first.assertions.total == 512 &&
		threaded_second.outcome == entry_outcome_e::passed && threaded_second.assertions.total == 512 &&
		evidence_value(threaded_first, "reporting_threads") == "4" &&
		evidence_value(threaded_second, "reporting_threads") == "4",
		"threaded assertion aggregation lost events");
	require(evidence_value(threaded_first, "ledger_digest") ==
		evidence_value(threaded_second, "ledger_digest"),
		"threaded assertion aggregation is not deterministic");
	for (const auto mode : {"empty", "fabricated", "truncated", "invalid_handle", "overflow",
		"zero_assertions", "count_mismatch", "identity_mismatch", "not_finalized",
		"duplicate_finalize", "late_write", "count_overflow", "duplicate_evidence",
		"unknown_top_field", "unknown_assertion_field", "unknown_ledger_field",
		"invalid_digest", "ledger_evidence_mismatch", "exit_evidence_mismatch",
		"first_failure_on_pass", "empty_first_failure_on_pass",
		"failed_without_first_failure", "not_run_mixed",
		"reporting_thread_overflow"}) {
		const auto rejected = execute_mode(fixture, source, mode);
		require(rejected.outcome == entry_outcome_e::malformed_result,
			"invalid assertion result did not fail as malformed");
		require(rejected.assertions.total == 0 && rejected.assertions.passed == 0 &&
			rejected.assertions.failed == 0 && rejected.assertions.skipped == 0 &&
			!rejected.assertions.not_run && rejected.evidence.empty(),
			"malformed assertion result retained partially accepted child fields");
	}
	const auto oversized = execute_mode(fixture, source, "oversize_result");
	require(oversized.outcome == entry_outcome_e::failed &&
		oversized.error.find("capture limit") != std::string::npos,
		"oversized result pipe did not preserve its bounded capture failure");
}

void validate_result_pipe_failures() {
	using namespace testlab_runtime;
	adapter_control_t control;
	control.entry_id = "fixture.pipe";
	control.source_target = "assertion_telemetry_fixture";
	control.build_identity.assign(64, '1');
	assertion_telemetry::entry_session_t session;
	std::string error;
	require(assertion_telemetry::begin_entry(control.entry_id, control.source_target, session, error),
		"pipe fixture ledger could not begin");
	assertion_telemetry::record_assertion(true, "pipe fixture assertion", __FILE__, __LINE__);
	session.finalize(0);
	const auto report = session.snapshot();
	session.close();
	control.result_handle = reinterpret_cast<std::uintptr_t>(INVALID_HANDLE_VALUE);
	require(!write_result_envelope(control, 0, 1, report, error) && !error.empty(),
		"invalid result handle was accepted");
	HANDLE read_handle = nullptr;
	HANDLE write_handle = nullptr;
	require(CreatePipe(&read_handle, &write_handle, nullptr, 0) != FALSE,
		"broken-pipe fixture could not create a pipe");
	CloseHandle(read_handle);
	control.result_handle = reinterpret_cast<std::uintptr_t>(write_handle);
	error.clear();
	const bool written = write_result_envelope(control, 0, 1, report, error);
	CloseHandle(write_handle);
	require(!written && !error.empty(), "broken result pipe was accepted");
}

void expect_manifest_rejected(const fixture_root_t& fixture, const json& value, std::string_view label) {
	static std::uint32_t sequence = 0;
	const auto path = fixture.path() / (std::wstring(L"malformed-") + std::to_wstring(++sequence) + L".json");
	write_text(path, value.dump());
	const auto loaded = load_manifest(fixture.path(), path);
	require(!loaded.accepted && !loaded.error.empty(), std::string("malformed manifest was accepted: ") + std::string(label));
}

void malformed_manifest_matrix(const fixture_root_t& fixture, const json& valid) {
	{
		auto value = valid;
		value["schema"] = "unknown";
		expect_manifest_rejected(fixture, value, "schema");
	}
	{
		auto value = valid;
		value["version"] = 1;
		expect_manifest_rejected(fixture, value, "version");
	}
	{
		auto value = valid;
		value["build_identity"] = std::string(64, 'A');
		expect_manifest_rejected(fixture, value, "build_identity");
	}
	{
		auto value = valid;
		value["contract_identity"] = "short";
		expect_manifest_rejected(fixture, value, "contract_identity");
	}
	{
		auto value = valid;
		value["entries"] = json::array();
		expect_manifest_rejected(fixture, value, "empty_entries");
	}
	{
		auto value = valid;
		value["unknown"] = true;
		expect_manifest_rejected(fixture, value, "unknown_root_field");
	}
	{
		auto value = valid;
		value["entries"][0]["unknown"] = true;
		expect_manifest_rejected(fixture, value, "unknown_entry_field");
	}
	{
		auto value = valid;
		value["entries"][1]["id"] = value["entries"][0]["id"];
		expect_manifest_rejected(fixture, value, "duplicate_id");
	}
	{
		auto value = valid;
		value["entries"][1]["source_target"] = value["entries"][0]["source_target"];
		expect_manifest_rejected(fixture, value, "duplicate_source_target");
	}
	{
		auto value = valid;
		value["entries"][1]["executable_relative_path"] = value["entries"][0]["executable_relative_path"];
		expect_manifest_rejected(fixture, value, "duplicate_executable");
	}
	{
		auto value = valid;
		value["entries"][0]["build_identity"] = std::string(64, '1');
		expect_manifest_rejected(fixture, value, "entry_build_identity");
	}
	{
		auto value = valid;
		value["entries"][0]["category"] = "unknown";
		expect_manifest_rejected(fixture, value, "unknown_category");
	}
	{
		auto value = valid;
		value["entries"][0]["executable_relative_path"] = "../escape.exe";
		expect_manifest_rejected(fixture, value, "traversal");
	}
	{
		auto value = valid;
		value["entries"][0]["executable_relative_path"] = "C:/escape.exe";
		expect_manifest_rejected(fixture, value, "absolute_path");
	}
	{
		auto value = valid;
		value["entries"][0]["executable_relative_path"] = "directory/../escape.exe";
		expect_manifest_rejected(fixture, value, "normalized_traversal");
	}
	{
		auto value = valid;
		value["entries"][0]["executable_relative_path"] = "fixture.exe:stream.exe";
		expect_manifest_rejected(fixture, value, "alternate_data_stream");
	}
	{
		auto value = valid;
		value["entries"][0]["working_directory_relative_path"] = "../escape";
		expect_manifest_rejected(fixture, value, "working_directory_traversal");
	}
	{
		auto value = valid;
		value["entries"][0]["safety"]["requires_network"] = true;
		expect_manifest_rejected(fixture, value, "network_flag");
	}
	{
		auto value = valid;
		value["entries"][0]["safety"]["requires_driver"] = true;
		expect_manifest_rejected(fixture, value, "driver_flag");
	}
	{
		auto value = valid;
		value["entries"][0]["safety"]["launches_application"] = true;
		expect_manifest_rejected(fixture, value, "application_flag");
	}
	{
		auto value = valid;
		value["entries"][0]["safety"]["launches_bootstrap"] = true;
		expect_manifest_rejected(fixture, value, "bootstrap_flag");
	}
	{
		auto value = valid;
		value["entries"][0]["safety"]["performs_packaging"] = true;
		expect_manifest_rejected(fixture, value, "packaging_flag");
	}
	{
		auto value = valid;
		value["entries"][0]["safety"]["performs_deployment"] = true;
		expect_manifest_rejected(fixture, value, "deployment_flag");
	}
	{
		auto value = valid;
		value["entries"][0]["safety"]["performs_live_operation"] = true;
		expect_manifest_rejected(fixture, value, "live_operation_flag");
	}
	{
		auto value = valid;
		value["entries"][0]["safety"]["performs_debugger_operation"] = true;
		expect_manifest_rejected(fixture, value, "debugger_operation_flag");
	}
	{
		auto value = valid;
		value["entries"][0]["safety"]["executes_target_artifact"] = true;
		expect_manifest_rejected(fixture, value, "target_execution_flag");
	}
	{
		auto value = valid;
		value["entries"][0]["safety"]["mutates_source_or_repository"] = true;
		expect_manifest_rejected(fixture, value, "repository_mutation_flag");
	}
	{
		auto value = valid;
		value["entries"][0]["safety"]["unknown"] = false;
		expect_manifest_rejected(fixture, value, "unknown_safety_field");
	}
	{
		auto value = valid;
		value["entries"][0]["expected_result_schema"] = "unknown";
		expect_manifest_rejected(fixture, value, "result_schema");
	}
	{
		auto value = valid;
		value["entries"][0]["requirement_ids"] = json::array({"bad"});
		expect_manifest_rejected(fixture, value, "requirement_id");
	}
	{
		auto value = valid;
		value["entries"][0]["requirement_ids"] = json::array({"HAR-01", "HAR-01"});
		expect_manifest_rejected(fixture, value, "duplicate_requirement");
	}
	{
		auto value = valid;
		value["entries"][0]["source_files"] = json::array({"../escape.cpp"});
		expect_manifest_rejected(fixture, value, "source_path");
	}
	{
		auto value = valid;
		value["entries"][0]["runtime_files"] = json::array({{
			{"relative_path", "../escape.bin"}, {"size", 1}, {"sha256", std::string(64, '0')}
		}});
		expect_manifest_rejected(fixture, value, "runtime_file_path");
	}
	{
		auto value = valid;
		value["entries"][0]["runtime_files"] = json::array({{
			{"relative_path", "fixture.bin"}, {"size", 0}, {"sha256", std::string(64, '0')}
		}});
		expect_manifest_rejected(fixture, value, "runtime_file_size");
	}
	{
		auto value = valid;
		value["entries"][0]["arguments"] = json::array({"--aida-c03-result-handle=1"});
		expect_manifest_rejected(fixture, value, "reserved_argument");
	}
	{
		auto value = valid;
		value["entries"][0]["arguments"] = json::array({"line\nbreak"});
		expect_manifest_rejected(fixture, value, "argument_newline");
	}
	{
		auto value = valid;
		value["entries"][0]["max_wall_ms"] = 99;
		expect_manifest_rejected(fixture, value, "wall_limit");
	}
	{
		auto value = valid;
		value["entries"][0]["max_wall_ms"] = 1800000;
		expect_manifest_rejected(fixture, value, "unauthorized_wall_override");
	}
	{
		auto value = valid;
		value["entries"][0]["max_wall_ms"] = 1800001;
		expect_manifest_rejected(fixture, value, "over_wall_limit");
	}
	{
		auto value = valid;
		value["entries"][0]["max_private_bytes"] = 1;
		expect_manifest_rejected(fixture, value, "memory_limit");
	}
	{
		auto value = valid;
		value["entries"][0].erase("max_active_processes");
		expect_manifest_rejected(fixture, value, "missing_active_process_limit");
	}
	{
		auto value = valid;
		value["entries"][0]["max_active_processes"] = 0;
		expect_manifest_rejected(fixture, value, "zero_active_process_limit");
	}
	{
		auto value = valid;
		value["entries"][0]["max_active_processes"] = 5;
		expect_manifest_rejected(fixture, value, "over_active_process_limit");
	}
	{
		auto value = valid;
		value["entries"][0]["max_active_processes"] = 4;
		expect_manifest_rejected(fixture, value, "unauthorized_multi_process_limit");
	}
	{
		auto value = valid;
		for (auto& entry : value["entries"]) {
			if (entry.at("id") == "decompiler.quality_scorer") {
				entry["max_active_processes"] = 3;
				break;
			}
		}
		expect_manifest_rejected(fixture, value, "noncanonical_quality_process_limit");
	}
	{
		auto value = valid;
		for (auto& entry : value["entries"]) {
			if (entry.at("id") == "decompiler.quality_scorer") {
				entry["max_wall_ms"] = 120000;
				break;
			}
		}
		expect_manifest_rejected(fixture, value, "noncanonical_quality_wall_limit");
	}
	{
		auto value = valid;
		value["entries"][0]["max_result_bytes"] = 0;
		expect_manifest_rejected(fixture, value, "result_limit");
	}
}

void phase(std::string_view name) {
	std::cerr << "testlab_phase=" << name << std::endl;
}

}

bool run_testlab_integration_harness(const testlab_integration_paths_t& paths, std::string& failure) {
	try {
		phase("assertion_telemetry_contract_begin");
		assertion_telemetry::fixtures::validate_assertion_telemetry_contract();
		phase("result_pipe_failures_begin");
		validate_result_pipe_failures();
		phase("outcome_contract_begin");
		validate_testlab_outcome_contract();
		phase("paths_begin");
		require(!paths.fake_adapter_path.empty() && !paths.scratch_root.empty(),
			"Test Lab integration paths are incomplete");
		phase("fixture_root_begin");
		fixture_root_t fixture(paths.scratch_root);
		phase("materialize_manifest_begin");
		std::string manifest_hash;
		const auto manifest_json = materialize_manifest(fixture, paths.fake_adapter_path, manifest_hash);
		phase("load_manifest_begin");
		const auto loaded = load_manifest(fixture.path(), fixture.path() / L"manifest.json", manifest_hash);
		phase("outcome_matrix_begin");
		validate_outcome_matrix(fixture, loaded);
		phase("assertion_result_matrix_begin");
		validate_assertion_result_matrix(fixture, loaded);
		phase("malformed_manifest_matrix_begin");
		malformed_manifest_matrix(fixture, manifest_json);
		phase("wrong_hash_begin");
		const auto wrong_hash = load_manifest(fixture.path(), fixture.path() / L"manifest.json", std::string(64, '0'));
		require(!wrong_hash.accepted, "stale manifest package hash was accepted");
		phase("complete");
		failure.clear();
		return true;
	} catch (const std::exception& error) {
		failure = error.what();
		return false;
	} catch (...) {
		failure = "Test Lab integration harness failed with a non-standard exception";
		return false;
	}
}

}

int main(int argc, char** argv) {
	if (argc != 3) {
		std::cerr << "usage: harness_testlab_integration <fake-adapter> <scratch-root>\n";
		return 2;
	}
	aida::analysis::c03_test::testlab_integration_paths_t paths;
	paths.fake_adapter_path = std::filesystem::u8path(argv[1]);
	paths.scratch_root = std::filesystem::u8path(argv[2]);
	std::string failure;
	if (!aida::analysis::c03_test::run_testlab_integration_harness(paths, failure)) {
		std::cerr << failure << '\n';
		return 1;
	}
	return 0;
}
