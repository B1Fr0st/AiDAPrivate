#include <windows.h>

#include "../assertion_telemetry/assertion_telemetry.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>

namespace {

using aida::analysis::c03_test::assertion_telemetry::record_assertion;
using json = nlohmann::json;

void require(const bool condition, const std::string_view message)
{
	record_assertion(condition, message, __FILE__, __LINE__);
	if (!condition)
		throw std::runtime_error(std::string(message));
}

std::string ascii_lower(std::string value)
{
	std::transform(value.begin(), value.end(), value.begin(), [](const unsigned char character) {
		return static_cast<char>(std::tolower(character));
	});
	return value;
}

std::wstring ordinal_lower(std::wstring value)
{
	if (!value.empty())
		CharLowerBuffW(value.data(), static_cast<DWORD>(value.size()));
	return value;
}

bool path_is_within(const std::filesystem::path& root,
	const std::filesystem::path& candidate)
{
	auto root_text = ordinal_lower(root.native());
	auto candidate_text = ordinal_lower(candidate.native());
	if (candidate_text == root_text)
		return true;
	if (root_text.empty())
		return false;
	if (root_text.back() != L'\\' && root_text.back() != L'/')
		root_text.push_back(L'\\');
	return candidate_text.size() > root_text.size() &&
		candidate_text.compare(0, root_text.size(), root_text) == 0;
}

std::filesystem::path canonical_root(const char* input)
{
	std::error_code error;
	auto root = std::filesystem::weakly_canonical(
		std::filesystem::absolute(std::filesystem::u8path(input), error), error);
	require(!error && !root.empty(), "policy root resolves canonically");
	const DWORD attributes = GetFileAttributesW(root.c_str());
	require(attributes != INVALID_FILE_ATTRIBUTES &&
		(attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
		(attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0,
		"policy root is a non-reparse directory");
	return root;
}

std::filesystem::path resolve_file(const std::filesystem::path& root,
	const std::filesystem::path& relative)
{
	require(!relative.empty() && !relative.is_absolute() &&
		!relative.has_root_name() && !relative.has_root_directory(),
		"policy source path is relative");
	for (const auto& component : relative)
		require(component != L"." && component != L".." && !component.empty(),
			"policy source path has no traversal component");
	std::error_code error;
	const auto path = std::filesystem::weakly_canonical(root / relative, error);
	require(!error && path_is_within(root, path),
		"policy source resolves under the staged root");
	const DWORD attributes = GetFileAttributesW(path.c_str());
	require(attributes != INVALID_FILE_ATTRIBUTES &&
		(attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0,
		"policy source is present and non-reparse");
	return path;
}

std::string read_bounded(const std::filesystem::path& root,
	const std::filesystem::path& relative, const std::uint64_t maximum)
{
	const auto path = resolve_file(root, relative);
	std::error_code error;
	const auto size = std::filesystem::file_size(path, error);
	require(!error && size != 0 && size <= maximum,
		"policy source size is bounded");
	std::ifstream input(path, std::ios::binary);
	require(static_cast<bool>(input), "policy source opened");
	std::string bytes(static_cast<std::size_t>(size), '\0');
	input.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
	require(static_cast<bool>(input) &&
		input.gcount() == static_cast<std::streamsize>(bytes.size()),
		"policy source read completed");
	return bytes;
}

json parse_json(const std::string_view bytes, const std::string_view label)
{
	try {
		return json::parse(bytes.begin(), bytes.end());
	} catch (const json::exception& error) {
		throw std::runtime_error(std::string(label) + " is invalid JSON: " + error.what());
	}
}

const json& json_member(const json& value, const std::string_view key,
	const std::string_view label)
{
	require(value.is_object(), std::string(label) + " is an object");
	const auto found = value.find(std::string(key));
	require(found != value.end(),
		std::string(label) + " contains field: " + std::string(key));
	return *found;
}

std::size_t json_count(const json& value, const std::string_view key,
	const std::string_view label)
{
	const auto& member = json_member(value, key, label);
	require(member.is_number_unsigned() || member.is_number_integer(),
		std::string(label) + " integer field: " + std::string(key));
	const auto number = member.get<std::int64_t>();
	require(number >= 0, std::string(label) + " nonnegative field: " + std::string(key));
	return static_cast<std::size_t>(number);
}

std::set<std::string> json_names(const json& value, const std::string_view label)
{
	require(value.is_array(), std::string(label) + " is an array");
	std::set<std::string> names;
	for (const auto& item : value) {
		require(item.is_string() && !item.get_ref<const std::string&>().empty(),
			std::string(label) + " contains valid names");
		require(names.insert(item.get<std::string>()).second,
			std::string(label) + " contains unique names");
	}
	return names;
}

std::size_t occurrence_count(const std::string_view bytes,
	const std::string_view token)
{
	require(!token.empty(), "policy occurrence token is nonempty");
	std::size_t count = 0;
	std::size_t cursor = 0;
	while ((cursor = bytes.find(token, cursor)) != std::string_view::npos) {
		++count;
		cursor += token.size();
	}
	return count;
}

void require_contains(const std::string_view bytes, const std::string_view token,
	const std::string_view label)
{
	require(bytes.find(token) != std::string_view::npos,
		std::string(label) + " contains required token: " + std::string(token));
}

void require_absent(const std::string_view bytes, const std::string_view token,
	const std::string_view label)
{
	require(bytes.find(token) == std::string_view::npos,
		std::string(label) + " excludes forbidden token: " + std::string(token));
}

void require_exact_count(const std::string_view bytes,
	const std::string_view token, const std::size_t expected,
	const std::string_view label)
{
	require(occurrence_count(bytes, token) == expected,
		std::string(label) + " has exact token cardinality for: " + std::string(token));
}

void require_ordered(const std::string_view bytes,
	const std::initializer_list<std::string_view> tokens,
	const std::string_view label)
{
	std::size_t cursor = 0;
	for (const auto token : tokens) {
		const auto found = bytes.find(token, cursor);
		require(found != std::string_view::npos,
			std::string(label) + " contains ordered token: " + std::string(token));
		cursor = found + token.size();
	}
}

std::string_view slice_between(const std::string_view bytes,
	const std::string_view begin_token, const std::string_view end_token,
	const std::string_view label)
{
	const auto begin = bytes.find(begin_token);
	const auto end = begin == std::string_view::npos
		? std::string_view::npos : bytes.find(end_token, begin + begin_token.size());
	require(begin != std::string_view::npos && end != std::string_view::npos && end > begin,
		std::string(label) + " is isolated by stable boundaries");
	return bytes.substr(begin, end - begin);
}

void require_clean_source(const std::string_view bytes,
	const std::string_view label)
{
	const auto lowered = ascii_lower(std::string(bytes));
	for (const auto token : std::array<std::string_view, 9>{
		"todo", "fixme", "fake pass", "schema-only handler",
		"placeholder result", "fabricated result", "hardcoded pass",
		"not implemented", "_stub"})
		require_absent(lowered, token, label);
}

void verify_message_pump(const std::string_view main_source)
{
	require_exact_count(main_source,
		"kAidaQueuedPeekFlags = PM_REMOVE | PM_QS_INPUT | PM_QS_POSTMESSAGE | PM_QS_PAINT | PM_QS_SENDMESSAGE",
		1, "message pump queued flags");
	require_exact_count(main_source,
		"kAidaSendOnlyPeekFlags = PM_REMOVE | PM_QS_SENDMESSAGE",
		1, "message pump send-only flags");
	const auto pump = slice_between(main_source,
		"aida_tracer::mark_render_phase(\"peek_message_probe\")",
		"aida_tracer::mark_render_phase(\"peek_message_done\")",
		"primary message pump");
	require_ordered(pump, {
		"GetQueueStatus(QS_ALLINPUT)",
		"if (queue_current == 0)",
		"set_peek_call_shape(kAidaQueuedPeekFlags, nullptr)",
		"if (send_only_pending)",
		"PeekMessage(&sent_probe, nullptr, 0U, 0U, kAidaSendOnlyPeekFlags)",
		"const UINT peek_remove_flags = kAidaQueuedPeekFlags",
		"PeekMessage(&msg, peek_filter, 0U, 0U, peek_remove_flags)"
	}, "primary message pump");
	const auto empty_queue = slice_between(pump,
		"if (queue_current == 0)", "const bool send_message_pending",
		"empty-queue branch");
	require_contains(empty_queue,
		"set_peek_call_shape(kAidaQueuedPeekFlags, nullptr)",
		"empty-queue branch");
	require_absent(empty_queue, "break", "empty-queue branch");
	require_absent(empty_queue, "continue", "empty-queue branch");
	require_absent(empty_queue, "return", "empty-queue branch");
	require_absent(pump, "PM_NOREMOVE", "primary message pump");
}

void verify_contract_source(const std::string_view contracts)
{
	require_absent(contracts, "\"py_eval\"", "generated MCP contract");
	require_absent(contracts, "ida://", "generated MCP contract");
	require_absent(contracts, "http://", "generated MCP contract");
	require_absent(contracts, "https://", "generated MCP contract");
	require_absent(contracts, "file://", "generated MCP contract");
	require_absent(contracts, "\"$ref\"", "generated MCP contract");
	require_exact_count(contracts,
		"constexpr contract_descriptor_t k_contracts[] = {", 1,
		"generated MCP descriptor table");
	require_exact_count(contracts,
		"const contract_descriptor_t* contracts() noexcept", 1,
		"generated MCP descriptor accessor");
	require_exact_count(contracts,
		"std::size_t contract_count() noexcept", 1,
		"generated MCP descriptor count accessor");
	require_exact_count(contracts,
		"const contract_descriptor_t* find_contract(std::string_view name) noexcept", 1,
		"generated MCP descriptor lookup");
}

void verify_browser_policy(const std::string_view browser)
{
	require_ordered(browser, {
		"inline bool open_url_external(const std::string& url)",
		"aida::burp::camoufox::ensure_ready()",
		"aida::burp::camoufox::navigate(url, \"domcontentloaded\", 45000)"
	}, "Camoufox-only browser launch");
	for (const auto token : std::array<std::string_view, 10>{
		"resolve_default_browser", "launch_via_shell_token",
		"shell_execute_via_explorer", "com_ptr_t", "ShellExecuteW",
		"ShellExecuteEx", "IWebBrowser2", "CoCreateInstance",
		"chrome.exe", "msedge.exe"})
		require_absent(browser, token, "Camoufox-only browser launch");
	require_absent(browser, "firefox.exe", "Camoufox-only browser launch");
}

void verify_customer_launch_policy(const std::string_view deploy)
{
	const auto lowered = ascii_lower(std::string(deploy));
	for (const auto token : std::array<std::string_view, 7>{
		"invoke-aidapeinmemory", "aida_fileless_launch",
		"invoke-reflectivepeinjection", "virtualallocex",
		"writeprocessmemory", "direct entrypoint invocation",
		"powershell-hosted aida"})
		require_absent(lowered, token, "customer deployment");
	for (const auto token : std::array<std::string_view, 12>{
		"invoke-camoufoxfrozenmcpcontractvalidation",
		"assert-noreversemcpsourceleak",
		"aida_camoufox_sidecar_sha256",
		"aida_camoufox_sidecar_size",
		"aida_camoufox_sidecar_exe_rel",
		"aida_camoufox_mcp_sha256",
		"aida_camoufox_mcp_size",
		"aida_camoufox_mcp_rel",
		"aida_camoufox_executable",
		"aida_camoufox_mcp_executable",
		"camoufox_mcp_hash_required",
		"camoufox_only_delivery_complete"})
		require_contains(lowered, token, "customer deployment");
	require_contains(deploy,
		"bootstrap-artifacts/[^[:space:]]+\\.pkg",
		"raw executable-package rejection");
}

void verify_surface_authority(const std::filesystem::path& root,
	const std::string_view generator, const std::string_view verifier,
	const std::string_view ledger_bytes, const std::string_view baseline_bytes,
	const std::string_view final_bytes)
{
	for (const auto token : std::array<std::string_view, 19>{
		"$unresolvedRegistrationEvidence.Count -ne 0",
		"Unresolved public MCP registrations remain",
		"resolved_helper_template_count = $resolvedHelperRecords.Count",
		"resolved_helper_registration_count = $resolvedHelperRegistrationCount",
		"unresolved_registration_count = $unresolvedRegistrationEvidence.Count",
		"dynamic_registration_templates = @($unresolvedRegistrationEvidence",
		"unresolved_dynamic_templates = $unresolvedRegistrationEvidence.Count",
		"$expectedResolvedHelperNames = @('register_direct_alias', 'register_dispatch_alias')",
		"$resolvedHelperRegistrationCount -ne 110",
		"concrete_registration_names = @($concrete.name)",
		"responsibility = 'production_mcp_registry_fixture'",
		"responsibility = 'combined_decompiler_quality_pipeline'",
		"replacement_evidence = $replacementEvidence.ToArray()",
		"sha256 = Get-FileSha256 $absolute",
		"Assert-SourceContains $cmakeSource @($retirement.cmake_markers)",
		"marker_count = @($allCmakeMarkers | Sort-Object -Unique).Count",
		"marker_sha256 = Get-StringListSha256 $allCmakeMarkers.ToArray()",
		"source_files = @($replacements | ForEach-Object",
		"Write-AtomicUtf8 $OutputPath"})
		require_contains(generator, token, "standalone surface generator");
	require_absent(generator,
		"unresolved_dynamic_templates = $resolvedHelperRecords.Count",
		"standalone surface terminal receipt");
	for (const auto token : std::array<std::string_view, 15>{
		"def archive_tool_names(", "verify_generated_contract_reproduction",
		"verify_current_surface_reproduction", "reproduced != checked_in",
		"generated MCP contract artifact is stale",
		"unresolved_registration_count", "resolved_registration_helpers",
		"replacement_evidence", "current C03 retirement responsibilities",
		"sha256_file(path)", "reject_external_refs", "MAX_COMPRESSION_RATIO",
		"parser.add_argument(\"--powershell\", type=Path, required=True)",
		"validate_absolute_executable(args.powershell",
		"ledger, root, powershell_path)"})
		require_contains(verifier, token, "combined authority reproduction verifier");

	const auto ledger = parse_json(ledger_bytes, "authority ledger");
	const auto baseline = parse_json(baseline_bytes, "surface baseline");
	const auto current = parse_json(final_bytes, "surface final inventory");
	require(json_member(ledger, "schema", "authority ledger") ==
		"aida.c03.authority-surface-ledger.v2", "authority ledger schema identity");
	const auto& reproduction = json_member(ledger, "current_surface_reproduction",
		"authority ledger");
	require(json_member(json_member(reproduction, "generator", "surface reproduction"),
		"path", "surface generator") ==
		"src/standalone/tests/analysis_workspace/generate_surface_manifest.ps1",
		"authority ledger generator path identity");
	require(json_member(json_member(reproduction, "baseline", "surface reproduction"),
		"path", "surface baseline") ==
		"src/standalone/tests/analysis_workspace/standalone_surface_baseline.json",
		"authority ledger baseline path identity");
	require(json_member(reproduction, "checked_in_path", "surface reproduction") ==
		"src/standalone/tests/analysis_workspace/standalone_surface_final.json",
		"authority ledger final path identity");
	require(json_count(baseline, "schema_version", "surface baseline") == 1U &&
		json_count(json_member(baseline, "mcp", "surface baseline"),
			"registration_count", "baseline MCP") == 289U,
		"surface baseline schema and MCP cardinality");
	require(json_count(current, "schema_version", "surface final inventory") == 2U,
		"surface final schema identity");

	const auto& mcp = json_member(current, "mcp", "surface final inventory");
	require(json_count(mcp, "registration_count", "final MCP") == 331U &&
		json_count(mcp, "unique_name_count", "final MCP") == 331U &&
		json_count(mcp, "generated_registration_count", "final MCP") == 92U &&
		json_count(mcp, "effective_registration_count", "final MCP") == 381U &&
		json_count(mcp, "unresolved_registration_count", "final MCP") == 0U &&
		json_count(mcp, "resolved_helper_template_count", "final MCP") == 2U &&
		json_count(mcp, "resolved_helper_registration_count", "final MCP") == 110U,
		"final MCP resolved/effective cardinality");
	const auto& unresolved = json_member(mcp, "dynamic_registration_templates", "final MCP");
	require(unresolved.is_array() && unresolved.empty(),
		"final MCP has exact zero unresolved registrations");
	std::set<std::string> registration_names;
	for (const auto& row : json_member(mcp, "registrations", "final MCP")) {
		require(row.is_object() && row.contains("name") && row.at("name").is_string(),
			"final MCP registration has a concrete name");
		require(registration_names.insert(row.at("name").get<std::string>()).second,
			"final MCP concrete registrations are unique");
	}
	require(registration_names.size() == 331U,
		"final MCP concrete registration inventory cardinality");
	const auto& helpers = json_member(mcp, "resolved_registration_helpers", "final MCP");
	require(helpers.is_array() && helpers.size() == 2U,
		"final MCP resolved helper inventory cardinality");
	std::unordered_map<std::string, std::size_t> helper_counts;
	std::set<std::string> helper_concrete;
	for (const auto& helper : helpers) {
		require(helper.is_object() && helper.value("expression", std::string()) == "alias",
			"resolved helper expression provenance");
		const auto name = helper.value("helper", std::string());
		const auto concrete = json_names(json_member(helper, "concrete_registration_names", name),
			name + " concrete registrations");
		require(!name.empty() && helper_counts.emplace(name, concrete.size()).second &&
			concrete.size() == json_count(helper, "concrete_registration_count", name),
			"resolved helper concrete cardinality");
		for (const auto& registration : concrete) {
			require(registration_names.count(registration) == 1U &&
				helper_concrete.insert(registration).second,
				"resolved helper has unique concrete public coverage");
		}
	}
	require(helper_counts == std::unordered_map<std::string, std::size_t>{
			{"register_direct_alias", 101U}, {"register_dispatch_alias", 9U}} &&
		helper_concrete.size() == 110U,
		"resolved helper exact provenance and concrete alias coverage");

	const auto& contract = json_member(json_member(ledger, "current_surface_contract",
		"authority ledger"), "dead_paths", "surface contract");
	const auto& dead = json_member(json_member(current, "public_surfaces", "surface final inventory"),
		"dead_paths", "public surfaces");
	const auto absent = json_names(json_member(dead, "absent_paths", "dead paths"),
		"absent dead paths");
	const auto replacements = json_names(json_member(dead, "replacement_paths", "dead paths"),
		"dead-path replacements");
	require(absent == json_names(json_member(contract, "absent", "dead-path contract"),
			"contract absent paths") && absent.size() == 6U,
		"dead-path exact retired inventory");
	require(replacements == json_names(json_member(contract, "replacements", "dead-path contract"),
			"contract replacements") && replacements.size() == 8U,
		"dead-path exact replacement inventory");
	for (const auto& relative : absent) {
		std::error_code error;
		require(!std::filesystem::exists(root / std::filesystem::u8path(relative), error),
			"retired path remains absent");
	}
	for (const auto& relative : replacements)
		resolve_file(root, std::filesystem::u8path(relative));
	const auto& retirements = json_member(dead, "retirements", "dead paths");
	const auto& replacement_evidence = json_member(dead, "replacement_evidence", "dead paths");
	require(retirements.is_array() && retirements.size() == 2U &&
		replacement_evidence.is_array() && replacement_evidence.size() == 8U,
		"dead-path responsibility and hash evidence cardinality");
	std::set<std::string> evidenced;
	for (const auto& row : replacement_evidence) {
		const auto path = row.value("path", std::string());
		const auto hash = row.value("sha256", std::string());
		require(replacements.count(path) == 1U && evidenced.insert(path).second &&
			hash.size() == 64U && std::all_of(hash.begin(), hash.end(), [](const unsigned char ch) {
				return std::isxdigit(ch) != 0;
			}), "dead-path replacement has a unique SHA-256 identity");
	}
	require(evidenced == replacements,
		"every exact replacement has source hash evidence");
}

void verify_manifest_registration(const std::string_view cmake_manifest)
{
	require_exact_count(cmake_manifest,
		"aida_c03_register_manifest_entry(", 57,
		"safe-headless manifest entry inventory");
	require_exact_count(cmake_manifest,
		"aida_c03_register_direct_test(", 13,
		"safe-headless direct-test inventory");
	for (const auto target : std::array<std::string_view, 6>{
		"TARGET aida_c03_a00_authority_surface_harness",
		"TARGET aida_c03_c08_c19_mcp_compatibility_harness",
		"TARGET aida_c03_surface_reconciliation_harness",
		"TARGET aida_c03_source_policy_scanner",
		"TARGET aida_c03_mcp_production_core_harness",
		"TARGET aida_c03_a06_decompiler_quality_scorer_harness"})
		require_exact_count(cmake_manifest, target, 1,
			"safe-headless canonical target registration");
	for (const auto source : std::array<std::string_view, 16>{
		"generated_entrypoints.cpp", "protocol_core_harness.cpp",
		"workspace_adapter_harness.cpp", "contract_generation_harness.cpp",
		"analysis_handlers_harness.cpp", "composite_handlers_harness.cpp",
		"core_handlers_harness.cpp", "debugger_handlers_harness.cpp",
		"memory_handlers_harness.cpp", "modify_handlers_harness.cpp",
		"python_handler_harness.cpp", "signature_handlers_harness.cpp",
		"stack_handlers_harness.cpp", "survey_handler_harness.cpp",
		"type_handlers_harness.cpp", "routing_extensions_harness.cpp"})
		require_exact_count(cmake_manifest, source, 1,
			"safe-headless MCP functional harness source");
	for (const auto source : std::array<std::string_view, 15>{
		"c03_compatibility_registration.cpp", "ida_contracts_generated.cpp",
		"mcp_server_integration.cpp", "handlers/analysis.cpp",
		"handlers/composite.cpp", "handlers/core.cpp", "handlers/debugger.cpp",
		"handlers/memory.cpp", "handlers/modify.cpp", "handlers/python.cpp",
		"handlers/routing_extensions.cpp", "handlers/signatures.cpp",
		"handlers/stack.cpp", "handlers/survey.cpp", "handlers/types.cpp"})
		require_contains(cmake_manifest, source,
			"safe-headless MCP production source registration");
	require_contains(cmake_manifest,
		"decompiler_quality_pipeline_main.cpp",
		"safe-headless live quality orchestration");
	require_contains(cmake_manifest,
		"decompiler_provider_matrix/provider_matrix.cpp",
		"safe-headless provider matrix registration");
	require_contains(cmake_manifest,
		"decompiler_quality_scorer_harness.cpp",
		"safe-headless scorer registration");
	for (const auto retired : std::array<std::string, 9>{
		std::string("driver_bridge_") + "stub",
		std::string("workspace_mcp_") + "harness",
		std::string("decompiler_quality_scorer_harness_") + "main",
		std::string("decompiler_provider_matrix/") + "main.cpp",
		std::string("materialize_quality_") + "selftest",
		std::string("c03_protocol_core_harness_") + "main.cpp.in",
		std::string("c03_provider_snapshot_harness_") + "main.cpp.in",
		std::string("handlers/routing_extensions_") + "harness.cpp",
		std::string("handlers/type_handlers_") + "harness.cpp"})
		require_absent(cmake_manifest, retired,
			"safe-headless retired source registration");
}

void verify_safe_headless_runtime(const std::string_view safe_headless,
	const std::string_view materializer, const std::string_view cmake_manifest,
	const std::string_view resource_cases)
{
	for (const auto token : std::array<std::string_view, 14>{
		"AIDA_C03_SAFE_HEADLESS_MANIFEST_SHA256",
		"expected_digest != k_packaged_manifest_sha256",
		"JOB_OBJECT_LIMIT_ACTIVE_PROCESS",
		"ActiveProcessLimit = entry.max_active_processes",
		"k_default_active_processes = 1",
		"k_multi_process_active_processes = 4",
		"k_default_wall_ms = 120'000U",
		"k_multi_process_wall_ms = 1'800'000U",
		"resource_contract_allowed",
		"PROC_THREAD_ATTRIBUTE_HANDLE_LIST",
		"JOB_OBJECT_LIMIT_PROCESS_MEMORY",
		"JOB_OBJECT_LIMIT_JOB_MEMORY",
		"CREATE_SUSPENDED",
		"CREATE_NO_WINDOW"})
		require_contains(safe_headless, token,
			"safe-headless runtime containment");
	require_absent(safe_headless, "ActiveProcessLimit = 4",
		"safe-headless global process containment");
	for (const auto token : std::array<std::string_view, 5>{
		"aida.c03.safe-headless.target-records.v2",
		"validate_resource_policy_cases", "target_resource_policy_accepts",
		"INVENTORY_SCHEMA", "--inventory"})
		require_contains(materializer, token,
			"safe-headless manifest materializer");
	for (const auto token : std::array<std::string_view, 8>{
		"--policy-cases", "if(\"${_aida_MAX_ACTIVE_PROCESSES}\" STREQUAL \"\")",
		"if(\"${_aida_MAX_WALL_MS}\" STREQUAL \"\")",
		"MATCHES \"^[1-4]$\"", "MAX_ACTIVE_PROCESSES 4",
		"MAX_WALL_MS 1800000", "scratch/quality/results",
		"AIDA_C03_COMPILER_MATRIX_CM_15"})
		require_contains(cmake_manifest, token,
			"safe-headless source/build contract");
	for (const auto token : std::array<std::string_view, 4>{
		"\"ordinary-default\"", "\"quality-approved\"",
		"\"unauthorized-multi-process\"",
		"\"unauthorized-wall-override\""})
		require_contains(resource_cases, token,
			"safe-headless resource policy fixture");
}

void verify_quality_pipeline(const std::string_view quality_pipeline,
	const std::string_view cmake_manifest)
{
	require_exact_count(quality_pipeline, "int main(int argc, char** argv)", 1,
		"quality pipeline executable entry");
	require_ordered(quality_pipeline, {
		"provider_matrix::run(config)",
		"matrix.output_files.size() != 4",
		"candidate.results.json",
		"ghidra-printc.results.json",
		"aida-current.results.json",
		"run_decompiler_quality_scorer_harness"
	}, "live quality provider/scorer pipeline");
	require_contains(quality_pipeline, "materialization.receipt.json",
		"live quality materialization identity");
	require_contains(quality_pipeline, "GetModuleFileNameW",
		"live quality executable identity");
	for (const auto legacy : std::array<std::string, 3>{
		std::string("fixtures/quality/") + "candidate.results.json",
		std::string("fixtures/quality/ghidra_") + "printc.results.json",
		std::string("fixtures/quality/aida_") + "current.results.json"})
		require_absent(cmake_manifest, legacy,
			"safe-headless prebaked provider evidence");
}

}

int main(int argc, char** argv)
{
	try {
		require(argc == 2, "source policy scanner argument contract");
		if (argc != 2)
			throw std::runtime_error("usage: source_policy_scanner <staged-root>");
		const auto root = canonical_root(argv[1]);
		const auto main_source = read_bounded(root,
			"src/standalone/src/main.cpp", 16ULL * 1024ULL * 1024ULL);
		const auto contracts = read_bounded(root,
			"src/standalone/src/core/mcp/compat/ida_contracts_generated.cpp",
			32ULL * 1024ULL * 1024ULL);
		const auto deploy = read_bounded(root,
			"deploy_to_server.ps1", 4ULL * 1024ULL * 1024ULL);
		const auto browser = read_bounded(root,
			"src/standalone/src/core/auth/auth_browser_launch.hpp",
			2ULL * 1024ULL * 1024ULL);
		const auto safe_headless = read_bounded(root,
			"src/standalone/src/core/testlab/test_lab_features_c03_safe_headless.cpp",
			4ULL * 1024ULL * 1024ULL);
		const auto materializer = read_bounded(root,
			"src/standalone/tests/c03/testlab_runtime/materialize_safe_headless_manifest.py",
			2ULL * 1024ULL * 1024ULL);
		const auto cmake_manifest = read_bounded(root,
			"cmake/aida_c03_safe_headless_manifest.cmake",
			8ULL * 1024ULL * 1024ULL);
		const auto resource_cases = read_bounded(root,
			"cmake/c03_safe_headless/target_resource_policy_cases.json",
			256ULL * 1024ULL);
		const auto quality_pipeline = read_bounded(root,
			"cmake/c03_safe_headless/decompiler_quality_pipeline_main.cpp",
			512ULL * 1024ULL);
		const auto surface_generator = read_bounded(root,
			"src/standalone/tests/analysis_workspace/generate_surface_manifest.ps1",
			4ULL * 1024ULL * 1024ULL);
		const auto authority_verifier = read_bounded(root,
			"tools/c03_authority/verify_authority_surface_ledger.py",
			2ULL * 1024ULL * 1024ULL);
		const auto authority_ledger = read_bounded(root,
			"tools/c03_authority/authority_surface_ledger.json",
			2ULL * 1024ULL * 1024ULL);
		const auto surface_baseline = read_bounded(root,
			"src/standalone/tests/analysis_workspace/standalone_surface_baseline.json",
			8ULL * 1024ULL * 1024ULL);
		const auto surface_final = read_bounded(root,
			"src/standalone/tests/analysis_workspace/standalone_surface_final.json",
			16ULL * 1024ULL * 1024ULL);
		verify_message_pump(main_source);
		verify_contract_source(contracts);
		verify_browser_policy(browser);
		verify_customer_launch_policy(deploy);
		verify_manifest_registration(cmake_manifest);
		verify_safe_headless_runtime(safe_headless, materializer,
			cmake_manifest, resource_cases);
		verify_quality_pipeline(quality_pipeline, cmake_manifest);
		verify_surface_authority(root, surface_generator, authority_verifier,
			authority_ledger, surface_baseline, surface_final);
		require_clean_source(main_source, "standalone main source");
		require_clean_source(contracts, "generated MCP contract source");
		require_clean_source(browser, "browser policy source");
		require_clean_source(safe_headless, "safe-headless runtime source");
		require_clean_source(cmake_manifest, "safe-headless CMake source");
		require_clean_source(quality_pipeline, "quality pipeline source");
		require_clean_source(authority_verifier, "authority reproduction verifier");
		return 0;
	} catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
		std::cerr << error.what() << '\n';
		return 1;
	}
}
