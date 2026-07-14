#pragma once

#include "test_lab.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace test_lab::c03_safe_headless {

inline constexpr std::uint32_t k_manifest_version = 2;
inline constexpr std::uint32_t k_result_version = 1;
inline constexpr std::uint64_t k_manifest_max_bytes = 8ULL * 1024ULL * 1024ULL;
inline constexpr std::uint64_t k_result_max_bytes = 1024ULL * 1024ULL;
inline constexpr std::uint64_t k_stream_max_bytes = 4ULL * 1024ULL * 1024ULL;

enum class entry_outcome_e : std::uint8_t {
	not_run = 0,
	missing = 1,
	passed = 2,
	failed = 3,
	timed_out = 4,
	crashed = 5,
	cancelled = 6,
	malformed_result = 7,
	integrity_failure = 8,
};

struct safety_contract_t {
	bool safe_headless = false;
	bool requires_driver = false;
	bool requires_network = false;
	bool launches_application = false;
	bool launches_bootstrap = false;
	bool performs_packaging = false;
	bool performs_deployment = false;
	bool performs_live_operation = false;
	bool performs_debugger_operation = false;
	bool executes_target_artifact = false;
	bool mutates_source_or_repository = false;
};

struct runtime_file_identity_t {
	std::filesystem::path relative_path;
	std::uint64_t size = 0;
	std::string sha256;
};

struct manifest_entry_t {
	std::string id;
	std::string category;
	std::vector<std::string> requirement_ids;
	std::string source_target;
	std::vector<std::string> source_files;
	std::vector<runtime_file_identity_t> runtime_files;
	std::filesystem::path executable_relative_path;
	std::filesystem::path working_directory_relative_path;
	std::vector<std::string> arguments;
	std::uint64_t executable_size = 0;
	std::string executable_sha256;
	std::string build_identity;
	std::uint32_t max_active_processes = 0;
	std::uint32_t max_wall_ms = 0;
	std::uint64_t max_private_bytes = 0;
	std::uint32_t max_stdout_bytes = 0;
	std::uint32_t max_stderr_bytes = 0;
	std::uint32_t max_result_bytes = 0;
	std::string expected_result_schema;
	safety_contract_t safety;
};

struct manifest_t {
	std::string build_identity;
	std::string contract_identity;
	std::vector<manifest_entry_t> entries;
};

struct manifest_load_result_t {
	bool accepted = false;
	manifest_t manifest;
	std::string manifest_sha256;
	std::string error;
};

struct assertion_counts_t {
	std::uint32_t total = 0;
	std::uint32_t passed = 0;
	std::uint32_t failed = 0;
	std::uint32_t skipped = 0;
	bool not_run = false;
};

struct evidence_field_t {
	std::string name;
	std::string value;
};

struct entry_result_t {
	std::string id;
	entry_outcome_e outcome = entry_outcome_e::not_run;
	assertion_counts_t assertions;
	std::uint64_t elapsed_us = 0;
	std::uint32_t process_id = 0;
	std::uint32_t exit_code = 0;
	std::uint64_t peak_job_memory_bytes = 0;
	std::string stdout_text;
	std::string stderr_text;
	std::vector<evidence_field_t> evidence;
	std::string error;
};

struct suite_result_t {
	std::string build_identity;
	std::string contract_identity;
	std::string manifest_sha256;
	std::uint64_t elapsed_us = 0;
	std::uint32_t not_run = 0;
	std::uint32_t missing = 0;
	std::uint32_t passed = 0;
	std::uint32_t failed = 0;
	std::uint32_t timed_out = 0;
	std::uint32_t crashed = 0;
	std::uint32_t cancelled = 0;
	std::uint32_t malformed_result = 0;
	std::uint32_t integrity_failure = 0;
	std::vector<entry_result_t> entries;
};

using cancellation_probe_t = std::function<bool()>;
using deadline_probe_t = std::function<bool()>;
using progress_sink_t = std::function<void(std::size_t, std::size_t, const entry_result_t&)>;

manifest_load_result_t load_manifest(const std::filesystem::path& approved_root,
	const std::filesystem::path& manifest_path,
	std::string expected_manifest_sha256 = {});
entry_result_t execute_entry(const std::filesystem::path& approved_root,
	const manifest_entry_t& entry,
	const cancellation_probe_t& cancellation = {},
	const deadline_probe_t& deadline = {});
suite_result_t execute_manifest(const std::filesystem::path& approved_root,
	const manifest_load_result_t& loaded,
	const cancellation_probe_t& cancellation = {},
	const progress_sink_t& progress = {});
std::string serialize_suite_result(const suite_result_t& result);
const char* outcome_name(entry_outcome_e outcome) noexcept;
outcome_e to_testlab_outcome(entry_outcome_e outcome) noexcept;

void request_cancellation() noexcept;
void reset_cancellation() noexcept;
bool cancellation_requested() noexcept;
bool is_feature(const feature_t& feature) noexcept;

}
