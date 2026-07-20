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
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

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

std::int64_t json_signed(const json& value, const std::string_view key,
	const std::string_view label)
{
	const auto& member = json_member(value, key, label);
	require(member.is_number_integer() || member.is_number_unsigned(),
		std::string(label) + " integer field: " + std::string(key));
	return member.get<std::int64_t>();
}

std::string json_string(const json& value, const std::string_view key,
	const std::string_view label)
{
	const auto& member = json_member(value, key, label);
	require(member.is_string() && !member.get_ref<const std::string&>().empty(),
		std::string(label) + " string field: " + std::string(key));
	return member.get<std::string>();
}

std::vector<std::string> json_string_vector(const json& value,
	const std::string_view label)
{
	require(value.is_array(), std::string(label) + " is an array");
	std::vector<std::string> output;
	output.reserve(value.size());
	for (const auto& item : value) {
		require(item.is_string() && !item.get_ref<const std::string&>().empty(),
			std::string(label) + " contains valid strings");
		output.push_back(item.get<std::string>());
	}
	return output;
}

void require_sha256(const std::string_view value, const std::string_view label)
{
	require(value.size() == 64U &&
		std::all_of(value.begin(), value.end(), [](const unsigned char character) {
			return std::isxdigit(character) != 0;
		}), std::string(label) + " is a SHA-256 identity");
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
	require(!token.empty(), std::string(label) + " required token is nonempty");
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

std::set<std::string> quoted_source_literals(const std::string_view bytes,
	const char quote, const std::string_view label)
{
	std::set<std::string> values;
	std::size_t cursor = 0;
	while (cursor < bytes.size()) {
		const auto begin = bytes.find(quote, cursor);
		if (begin == std::string_view::npos)
			break;
		const auto end = bytes.find(quote, begin + 1);
		require(end != std::string_view::npos && end > begin + 1,
			std::string(label) + " has closed nonempty quoted literals");
		require(values.emplace(bytes.substr(begin + 1, end - begin - 1)).second,
			std::string(label) + " has unique quoted literals");
		cursor = end + 1;
	}
	require(!values.empty(), std::string(label) + " has quoted literals");
	return values;
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

void verify_mcp_reachability_artifact(const std::filesystem::path& root,
	const json& ledger, const json& current)
{
	const auto& mcp = json_member(current, "mcp", "surface final inventory");
	const auto& reachability = json_member(mcp, "production_reachability", "final MCP");
	require(reachability.is_object() && reachability.size() == 13U &&
		json_count(reachability, "schema_version", "MCP reachability") == 1U &&
		json_count(reachability, "concrete_registration_count", "MCP reachability") == 331U &&
		json_count(reachability, "direct_registration_count", "MCP reachability") == 281U &&
		json_count(reachability, "generated_projection_count", "MCP reachability") == 50U,
		"MCP reachability schema and concrete partition");

	const auto& production_entry = json_member(reachability, "production_entry", "MCP reachability");
	require(production_entry.is_object() && production_entry.size() == 6U,
		"MCP production entry exact field inventory");
	const auto root_id = json_string(production_entry, "root_registrar_id", "production entry");
	require(json_string(production_entry, "file", "production entry") ==
		"src/standalone/src/core/ai/standalone_chat.cpp" &&
		json_string(production_entry, "expression", "production entry") ==
		"mcp_standalone::register_standalone_tools(s_mcp_server)" &&
		json_string(production_entry, "root_registrar_symbol", "production entry") ==
		"mcp_standalone::register_standalone_tools" &&
		json_count(production_entry, "line", "production entry") != 0U &&
		json_count(production_entry, "character_offset", "production entry") != 0U,
		"MCP production entry exact identity");

	const auto& registrars = json_member(reachability, "registrars", "MCP reachability");
	const auto& edges = json_member(reachability, "edges", "MCP reachability");
	require(registrars.is_array() && !registrars.empty() &&
		registrars.size() == json_count(reachability, "reachable_registrar_count", "MCP reachability") &&
		edges.is_array() && edges.size() ==
			json_count(reachability, "registrar_edge_count", "MCP reachability") &&
		registrars.size() == edges.size() + 1U,
		"MCP reachable registrar graph cardinality");
	std::unordered_map<std::string, const json*> registrar_by_id;
	std::unordered_map<std::string, std::string> registrar_parent;
	std::set<std::string> registrar_files;
	for (const auto& registrar : registrars) {
		require(registrar.is_object() && registrar.size() == 8U,
			"reachable registrar exact field inventory");
		const auto id = json_string(registrar, "id", "reachable registrar");
		require(registrar_by_id.emplace(id, &registrar).second,
			"reachable registrar identities are unique");
		const auto file = json_string(registrar, "file", "reachable registrar");
		registrar_files.insert(file);
		resolve_file(root, std::filesystem::u8path(file));
		require(json_count(registrar, "line", "reachable registrar") != 0U &&
			json_count(registrar, "body_start", "reachable registrar") <
				json_count(registrar, "body_end", "reachable registrar"),
			"reachable registrar source range");
		const auto chain = json_string_vector(
			json_member(registrar, "chain", "reachable registrar"), "reachable registrar chain");
		require(!chain.empty() && chain.front() == root_id && chain.back() == id &&
			std::set<std::string>(chain.begin(), chain.end()).size() == chain.size(),
			"reachable registrar chain is rooted and acyclic");
		const auto& parent = json_member(registrar, "parent_id", "reachable registrar");
		if (id == root_id) {
			require(parent.is_null() && chain.size() == 1U,
				"production registrar root has no parent");
		} else {
			require(parent.is_string() && !parent.get_ref<const std::string&>().empty() &&
				chain.size() >= 2U && chain[chain.size() - 2U] == parent.get<std::string>(),
				"reachable registrar parent agrees with its chain");
			registrar_parent.emplace(id, parent.get<std::string>());
		}
	}
	require(registrar_by_id.count(root_id) == 1U,
		"production registrar root is reachable");
	std::unordered_map<std::string, std::size_t> incoming;
	std::set<std::string> direct_edge_identities;
	for (const auto& edge : edges) {
		require(edge.is_object() && edge.size() == 7U,
			"direct registrar edge exact field inventory");
		const auto caller = json_string(edge, "caller_id", "registrar edge");
		const auto callee = json_string(edge, "callee_id", "registrar edge");
		const auto file = json_string(edge, "file", "registrar edge");
		const auto offset = json_count(edge, "character_offset", "registrar edge");
		require(registrar_by_id.count(caller) == 1U && registrar_by_id.count(callee) == 1U &&
			registrar_parent.count(callee) == 1U && registrar_parent.at(callee) == caller &&
			json_count(edge, "line", "registrar edge") != 0U &&
			!json_string(edge, "expression", "registrar edge").empty(),
			"registrar edge has exact reachable ownership");
		require(direct_edge_identities.insert(
			caller + "\t" + callee + "\t" + file + "\t" + std::to_string(offset)).second,
			"registrar edges have unique source identities");
		++incoming[callee];
	}
	for (const auto& [id, registrar] : registrar_by_id) {
		static_cast<void>(registrar);
		require(incoming[id] == (id == root_id ? 0U : 1U),
			"direct registrar graph is a rooted tree");
	}
	require_sha256(json_string(reachability, "row_binding_sha256", "MCP reachability"),
		"MCP reachability row fingerprint");
	require_sha256(json_string(reachability, "registrar_graph_sha256", "MCP reachability"),
		"MCP registrar graph fingerprint");

	const auto& route = json_member(reachability, "generated_route", "MCP reachability");
	require(route.is_object() && route.size() == 14U &&
		json_count(route, "node_count", "generated route") == 7U &&
		json_count(route, "edge_count", "generated route") == 7U &&
		json_count(route, "terminal_operation_count", "generated route") == 2U &&
		json_count(route, "binding_count", "generated route") == 92U &&
		json_count(route, "generated_compatibility_count", "generated route") == 88U &&
		json_count(route, "extension_count", "generated route") == 4U,
		"generated MCP route exact cardinality");
	const auto shared_id = json_string(route, "shared_terminal_definition_id", "generated route");
	const auto shared_parents = json_names(
		json_member(route, "shared_terminal_parent_ids", "generated route"),
		"generated route shared parents");
	require(shared_parents.size() == 2U,
		"generated route has exactly two shared-terminal parents");
	const auto& route_nodes = json_member(route, "nodes", "generated route");
	const auto& route_edges = json_member(route, "edges", "generated route");
	const auto& terminal_operations = json_member(route, "terminal_operations", "generated route");
	const auto& bindings = json_member(route, "bindings", "generated route");
	require(route_nodes.is_array() && route_nodes.size() == 7U &&
		route_edges.is_array() && route_edges.size() == 7U &&
		terminal_operations.is_array() && terminal_operations.size() == 2U &&
		bindings.is_array() && bindings.size() == 92U,
		"generated MCP route arrays match their cardinalities");
	std::unordered_map<std::string, const json*> route_node_by_id;
	std::string generated_parent;
	std::string extension_parent;
	for (const auto& node : route_nodes) {
		require(node.is_object() && node.size() == 7U,
			"generated route node exact field inventory");
		const auto id = json_string(node, "id", "generated route node");
		require(route_node_by_id.emplace(id, &node).second &&
			json_count(node, "line", "generated route node") != 0U &&
			json_count(node, "body_start", "generated route node") <
				json_count(node, "body_end", "generated route node"),
			"generated route node exact source identity");
		const auto symbol = json_string(node, "symbol", "generated route node");
		if (symbol.find("register_generated_tools") != std::string::npos) {
			require(generated_parent.empty(), "generated route has one generated branch registrar");
			generated_parent = id;
		}
		if (symbol.find("register_extension_tools") != std::string::npos) {
			require(extension_parent.empty(), "generated route has one extension branch registrar");
			extension_parent = id;
		}
	}
	require(route_node_by_id.count(root_id) == 1U &&
		route_node_by_id.count(shared_id) == 1U &&
		!generated_parent.empty() && !extension_parent.empty() &&
		shared_parents == std::set<std::string>{generated_parent, extension_parent},
		"generated route root, branches, and shared leaf identities");
	std::map<std::string, std::set<std::string>> route_incoming;
	std::set<std::string> route_adjacency;
	std::set<std::string> route_edge_identities;
	for (const auto& edge : route_edges) {
		require(edge.is_object() && edge.size() == 8U,
			"generated route edge exact field inventory");
		const auto caller = json_string(edge, "caller_id", "generated route edge");
		const auto callee = json_string(edge, "callee_id", "generated route edge");
		const auto file = json_string(edge, "file", "generated route edge");
		const auto offset = json_count(edge, "character_offset", "generated route edge");
		require(route_node_by_id.count(caller) == 1U && route_node_by_id.count(callee) == 1U &&
			json_count(edge, "line", "generated route edge") != 0U &&
			!json_string(edge, "expression", "generated route edge").empty(),
			"generated route edge exact source identity");
		require(route_edge_identities.insert(
			caller + "\t" + callee + "\t" + file + "\t" + std::to_string(offset)).second,
			"generated route edges have unique source identities");
		route_incoming[callee].insert(caller);
		route_adjacency.insert(caller + "\t" + callee);
	}
	for (const auto& [id, node] : route_node_by_id) {
		static_cast<void>(node);
		const auto& parents = route_incoming[id];
		if (id == root_id)
			require(parents.empty(), "generated route root has no parent");
		else if (id == shared_id)
			require(parents == shared_parents, "generated route shared leaf has exact parents");
		else
			require(parents.size() == 1U, "generated route non-shared node has one parent");
	}
	std::set<std::string> terminal_kinds;
	std::set<std::string> terminal_sources;
	for (const auto& operation : terminal_operations) {
		require(operation.is_object() && operation.size() == 6U,
			"generated terminal operation exact field inventory");
		require(json_string(operation, "caller_id", "generated terminal operation") == shared_id &&
			json_count(operation, "line", "generated terminal operation") != 0U,
			"generated terminal operation is owned by the shared leaf");
		const auto expression = json_string(operation, "expression", "generated terminal operation");
		const auto kind = expression.find("replace_tool") != std::string::npos
			? std::string("replace_tool")
			: expression.find("register_tool") != std::string::npos
				? std::string("register_tool") : std::string();
		require(!kind.empty() && terminal_kinds.insert(kind).second,
			"generated terminal operations are exact and unique");
		terminal_sources.insert(
			json_string(operation, "file", "generated terminal operation") + "\t" +
			std::to_string(json_count(operation, "character_offset", "generated terminal operation")));
	}
	require(terminal_sources.size() == 2U,
		"generated terminal operations have distinct source identities");

	std::unordered_map<std::string, const json*> binding_by_name;
	std::size_t compatibility_bindings = 0;
	std::size_t extension_bindings = 0;
	for (const auto& binding : bindings) {
		require(binding.is_object() && binding.size() == 6U,
			"generated route binding exact field inventory");
		const auto name = json_string(binding, "name", "generated route binding");
		require(binding_by_name.emplace(name, &binding).second &&
			json_string(binding, "registrar_id", "generated route binding") == shared_id,
			"generated per-name bindings are unique and terminate at the shared leaf");
		const auto branch = json_string(binding, "branch", "generated route binding");
		const auto chain = json_string_vector(
			json_member(binding, "chain", "generated route binding"),
			"generated route binding chain");
		require(chain.size() == 6U && chain.front() == root_id && chain.back() == shared_id &&
			std::set<std::string>(chain.begin(), chain.end()).size() == chain.size(),
			"generated per-name binding has an exact acyclic route chain");
		for (std::size_t index = 1U; index < chain.size(); ++index)
			require(route_adjacency.count(chain[index - 1U] + "\t" + chain[index]) == 1U,
				"generated per-name binding chain uses declared route edges");
		if (branch == "generated_compatibility") {
			require(chain[chain.size() - 2U] == generated_parent,
				"generated compatibility binding uses its exact branch");
			++compatibility_bindings;
		} else {
			require(branch == "extension" && chain[chain.size() - 2U] == extension_parent,
				"extension binding uses its exact branch");
			++extension_bindings;
		}
		require_sha256(json_string(binding, "chain_sha256", "generated route binding"),
			"generated route chain fingerprint");
	}
	require(compatibility_bindings == 88U && extension_bindings == 4U,
		"generated route binding branch partition");
	require_sha256(json_string(route, "route_sha256", "generated route"),
		"generated route fingerprint");
	require_sha256(json_string(route, "binding_sha256", "generated route"),
		"generated binding fingerprint");

	const auto& compatibility = json_member(
		json_member(current, "source_contracts", "surface final inventory"),
		"ida_compatibility", "source contracts");
	const auto& compatibility_rows = json_member(
		compatibility, "registrations", "IDA compatibility");
	require(compatibility_rows.is_array() && compatibility_rows.size() == 92U,
		"canonical generated compatibility row cardinality");
	std::set<std::string> canonical_names;
	for (const auto& row : compatibility_rows) {
		const auto name = json_string(row, "name", "canonical compatibility row");
		const auto found = binding_by_name.find(name);
		require(found != binding_by_name.end() && canonical_names.insert(name).second &&
			json_member(row, "production_reachability", "canonical compatibility row") ==
				*found->second,
			"canonical compatibility row has exact per-name production reachability");
	}
	require(canonical_names == json_names(
		json_member(mcp, "generated_union_names", "final MCP"), "generated MCP union"),
		"canonical reachability covers the exact 92-name union");

	const auto generated_only = json_names(
		json_member(mcp, "generated_only_names", "final MCP"), "generated-only MCP names");
	const auto& registrations = json_member(mcp, "registrations", "final MCP");
	require(registrations.is_array() && registrations.size() == 331U,
		"MCP concrete reachability row cardinality");
	std::set<std::string> projection_names;
	std::size_t direct_count = 0;
	std::size_t projection_count = 0;
	for (const auto& row : registrations) {
		const auto name = json_string(row, "name", "MCP concrete registration");
		const auto& source = json_member(row, "source", "MCP concrete registration");
		const auto offset = json_signed(source, "character_offset", "MCP registration source");
		const auto& binding = json_member(
			row, "production_reachability", "MCP concrete registration");
		const auto mode = json_string(binding, "mode", "MCP registration reachability");
		const auto chain = json_string_vector(
			json_member(binding, "chain", "MCP registration reachability"),
			"MCP registration reachability chain");
		require(!chain.empty() && chain.front() == root_id &&
			json_string(binding, "registrar_id", "MCP registration reachability") == chain.back(),
			"MCP registration binding has a rooted registrar chain");
		require_sha256(json_string(binding, "chain_sha256", "MCP registration reachability"),
			"MCP registration chain fingerprint");
		if (mode == "direct_registration") {
			require(binding.is_object() && binding.size() == 5U,
				"direct MCP binding exact field inventory");
			require(offset >= 0 && registrar_by_id.count(chain.back()) == 1U,
				"direct MCP registration binds a reachable registrar");
			resolve_file(root, std::filesystem::u8path(
				json_string(source, "file", "MCP registration source")));
			++direct_count;
		} else {
			require(binding.is_object() && binding.size() == 6U,
				"generated projection exact field inventory");
			require(mode == "generated_compatibility_projection" && offset == -1 &&
				binding_by_name.count(name) == 1U,
				"generated-only MCP registration has an exact route projection");
			const auto& generated = *binding_by_name.at(name);
			require(json_string(binding, "generated_branch", "MCP registration reachability") ==
					json_string(generated, "branch", "generated route binding") &&
				json_string(binding, "registrar_id", "MCP registration reachability") ==
					json_string(generated, "registrar_id", "generated route binding") &&
				json_string(binding, "registrar_symbol", "MCP registration reachability") ==
					json_string(generated, "registrar_symbol", "generated route binding") &&
				json_string(binding, "chain_sha256", "MCP registration reachability") ==
					json_string(generated, "chain_sha256", "generated route binding") &&
				json_member(binding, "chain", "MCP registration reachability") ==
					json_member(generated, "chain", "generated route binding"),
				"generated-only MCP projection equals its per-name route");
			projection_names.insert(name);
			++projection_count;
		}
	}
	require(direct_count == 281U && projection_count == 50U &&
		projection_names == generated_only,
		"MCP direct/generated-only production reachability partition");

	const auto source_files = json_names(
		json_member(reachability, "source_files", "MCP reachability"),
		"MCP reachability source files");
	auto expected_source_files = registrar_files;
	for (const auto file : std::array<std::string_view, 4>{
		"src/standalone/src/core/ai/standalone_chat.cpp",
		"src/standalone/src/core/mcp/mcp_standalone.cpp",
		"src/standalone/src/core/mcp/compat/c03_compatibility_registration.cpp",
		"src/standalone/src/core/mcp/compat/mcp_server_integration.cpp"})
		expected_source_files.emplace(file);
	require(source_files == expected_source_files,
		"MCP reachability source inventory is exact");
	for (const auto& file : source_files)
		resolve_file(root, std::filesystem::u8path(file));

	const auto& authority = json_member(
		json_member(json_member(ledger, "current_surface_contract", "authority ledger"),
			"mcp", "current surface contract"),
		"production_reachability", "current surface MCP");
	require(authority.is_object() && authority.size() == 17U,
		"reachability authority exact field inventory");
	for (const auto field : std::array<std::string_view, 16>{
		"schema_version", "concrete_registration_count", "direct_registration_count",
		"generated_projection_count", "reachable_registrar_count", "registrar_edge_count",
		"row_binding_sha256", "registrar_graph_sha256", "generated_route_node_count",
		"generated_route_edge_count", "generated_terminal_operation_count",
		"generated_binding_count", "generated_compatibility_count",
		"generated_extension_count", "generated_route_sha256", "generated_binding_sha256"}) {
		if (field == "generated_route_node_count")
			require(json_member(authority, field, "reachability authority") == route.at("node_count"),
				"reachability authority generated node count");
		else if (field == "generated_route_edge_count")
			require(json_member(authority, field, "reachability authority") == route.at("edge_count"),
				"reachability authority generated edge count");
		else if (field == "generated_terminal_operation_count")
			require(json_member(authority, field, "reachability authority") ==
				route.at("terminal_operation_count"),
				"reachability authority terminal count");
		else if (field == "generated_binding_count")
			require(json_member(authority, field, "reachability authority") == route.at("binding_count"),
				"reachability authority binding count");
		else if (field == "generated_compatibility_count")
			require(json_member(authority, field, "reachability authority") ==
				route.at("generated_compatibility_count"),
				"reachability authority compatibility count");
		else if (field == "generated_extension_count")
			require(json_member(authority, field, "reachability authority") == route.at("extension_count"),
				"reachability authority extension count");
		else if (field == "generated_route_sha256")
			require(json_member(authority, field, "reachability authority") == route.at("route_sha256"),
				"reachability authority route identity");
		else if (field == "generated_binding_sha256")
			require(json_member(authority, field, "reachability authority") == route.at("binding_sha256"),
				"reachability authority binding identity");
		else
			require(json_member(authority, field, "reachability authority") ==
				json_member(reachability, field, "MCP reachability"),
				"reachability authority field equals final MCP evidence");
	}
	const json expected_authority_entry = {
		{"file", production_entry.at("file")},
		{"expression", production_entry.at("expression")},
		{"root_registrar_symbol", production_entry.at("root_registrar_symbol")}
	};
	require(json_member(authority, "production_entry", "reachability authority") ==
		expected_authority_entry,
		"reachability authority production entry is exact");
}

void verify_surface_authority(const std::filesystem::path& root,
	const std::string_view generator, const std::string_view verifier,
	const std::string_view ledger_bytes, const std::string_view baseline_bytes,
	const std::string_view final_bytes)
{
	for (const auto token : std::initializer_list<std::string_view>{
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
		"Write-AtomicUtf8 $OutputPath",
		"function Test-CppDigitSeparator(",
		"function Get-CppMaskErrorContext(",
		"function Get-CppCodeMask(",
		"function Test-CppRegistrarDeclaration(",
		"function Get-CppRegistrarCalls(",
		"function Get-McpProductionReachability(",
		"(?:register|replace)_[A-Za-z0-9_]+",
		"Registrar declaration is forbidden in reachable code",
		"Indirect registrar edge",
		"$immediatePrevious",
		"$previousIndex",
		"registrar_character_offset",
		"C03 registrar body has an unclassified or missing edge",
		"production_reachability = $mcpProductionReachability",
		"shared_terminal_definition_id",
		"shared_terminal_parent_ids",
		"row_binding_sha256",
		"registrar_graph_sha256",
		"generated_projection_count",
		"character_offset = $absolute"})
		require_contains(generator, token, "standalone surface generator");
	require_absent(generator,
		"unresolved_dynamic_templates = $resolvedHelperRecords.Count",
		"standalone surface terminal receipt");
	for (const auto token : std::initializer_list<std::string_view>{
		"def archive_tool_names(", "verify_generated_contract_reproduction",
		"verify_current_surface_reproduction", "reproduced != checked_in",
		"generated MCP contract artifact is stale",
		"unresolved_registration_count", "resolved_registration_helpers",
		"replacement_evidence", "current C03 retirement responsibilities",
		"sha256_file(path)", "reject_external_refs", "MAX_COMPRESSION_RATIO",
		"parser.add_argument(\"--powershell\", type=Path, required=True)",
		"validate_absolute_executable(args.powershell",
		"ledger, root, powershell_path)",
		"def cpp_digit_separator(",
		"def cpp_mask_error_context(",
		"def cpp_code_mask(",
		"def cpp_registrar_declaration(",
		"def cpp_registrar_calls(",
		"def derive_cpp_reachability_graph(",
		"def derive_generated_compatibility_route(",
		"def verify_mcp_production_reachability(",
		"(?:register|replace)_[A-Za-z0-9_]+",
		"registrar declaration is forbidden in reachable code",
		"indirect registrar edge",
		"immediate_previous",
		"previous_index",
		"registrar_character_offset",
		"C03 registrar body has an unclassified or missing edge",
		"shared_terminal_definition_id",
		"shared_terminal_parent_ids",
		"row_binding_sha256",
		"registrar_graph_sha256",
		"generated_projection_count",
		"production_reachability"})
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
	verify_mcp_reachability_artifact(root, ledger, current);
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

void verify_safe_headless_driver_boundary(const std::string_view source)
{
	for (const auto token : std::array<std::string_view, 15>{
			"#if !defined(AIDA_C03_SAFE_HEADLESS_RUNTIME) || AIDA_C03_SAFE_HEADLESS_RUNTIME != 1",
			"#error AIDA_C03_SAFE_HEADLESS_RUNTIME_must_equal_1",
			"bool is_loaded()", "bool using_kernel_driver()",
			"bool attach(uint32_t)", "bool attach_additional(uint32_t)",
			"bool read_memory_for(uint32_t", "enumerate_modules_for(uint32_t)",
			"bool write_memory(uint64_t", "bool trigger_kernel_bsod(uint32_t",
			"bool verify_cross_ring_evidence(const uint8_t*",
			"capture_live_target_identity(std::uint32_t",
			"validate_live_target_identity(const live_target_identity_t&)",
			"validate_attached_target_identity(const live_target_identity_t&)",
			"refresh_attached_target_identity(const live_target_identity_t&"})
		require_contains(source, token,
			"safe-headless fail-closed driver boundary");
	for (const auto token : std::array<std::string_view, 8>{
			"standalone_driver.cpp", "DeviceIoControl", "CreateFileW(", "OpenProcess(",
			"ReadProcessMemory", "WriteProcessMemory", "NtReadVirtualMemory",
			"NtWriteVirtualMemory"})
		require_absent(source, token,
			"safe-headless driver or process operation");
}

void verify_self_guard_odr_contract(const std::string_view source)
{
	for (const auto function : std::array<std::string_view, 11>{
			"check_pid_self_impl", "check_address_self_impl", "check_binary_self_impl",
			"check_blocklist_impl", "decoy_guard_1", "decoy_guard_2",
			"decoy_guard_3", "decoy_guard_4", "decoy_guard_5", "decoy_guard_6",
			"self_guard_check_impl"})
		require_contains(source,
			std::string("__declspec(noinline) inline self_guard_result_t ") +
			std::string(function) + "(",
			"anti-tamper self-guard inline ODR contract");
}

void verify_manifest_registration(const std::string_view cmake_manifest,
                                  const std::string_view path_policy,
                                  const std::string_view path_identity,
                                  const std::string_view package_integration)
{
	require_exact_count(cmake_manifest,
		"aida_c03_register_manifest_entry(", 56,
		"safe-headless manifest entry inventory");
	require_exact_count(cmake_manifest,
		"aida_c03_register_direct_test(", 15,
		"safe-headless direct-test inventory");
	require_exact_count(cmake_manifest, "add_test(NAME", 4,
		"safe-headless explicit CTest declarations");
	require_exact_count(cmake_manifest,
		"add_test(NAME aida_c03_authority_surface_reproduction", 1,
		"combined authority reproduction CTest");
	require_exact_count(cmake_manifest,
		"set_tests_properties(aida_c03_authority_surface_reproduction PROPERTIES", 1,
		"combined authority reproduction properties");
	require_absent(cmake_manifest, "aida_c03_mcp_contract_generator_reproduction",
		"retired split contract reproduction CTest");
	const auto authority_test = slice_between(cmake_manifest,
		"add_test(NAME aida_c03_authority_surface_reproduction",
		"add_test(NAME aida_c03_package_distribution_policy",
		"combined authority reproduction CTest");
	for (const auto token : std::array<std::string_view, 12>{
		"COMMAND \"${_aida_python_executable}\"",
		"\"${CMAKE_SOURCE_DIR}/tools/c03_authority/verify_authority_surface_ledger.py\"",
		"--repository-root \"${CMAKE_SOURCE_DIR}\"",
		"--ledger \"${CMAKE_SOURCE_DIR}/tools/c03_authority/authority_surface_ledger.json\"",
		"--archive \"${_aida_authority_archive}\"",
		"--powershell \"${_aida_system_powershell}\"",
		"WORKING_DIRECTORY \"${CMAKE_CURRENT_SOURCE_DIR}\"",
		"TIMEOUT 600",
		"LABELS \"c03;c03_safe_headless;safe-headless;authority;surface;contract-reproduction\"",
		"RESOURCE_LOCK \"aida_c03_authority_surface_reproduction\"",
		"set_tests_properties(aida_c03_authority_surface_reproduction PROPERTIES",
		"add_test(NAME aida_c03_authority_surface_reproduction"})
		require_exact_count(authority_test, token, 1,
			"combined authority reproduction exact command and properties");
	require_absent(authority_test, "${Python3_EXECUTABLE}",
		"combined authority reproduction validated interpreter command");
	require_exact_count(cmake_manifest,
		"COMMAND \"${Python3_EXECUTABLE}\"", 0,
		"raw unvalidated Python command absence");
	for (const auto token : std::array<std::string_view, 18>{
		"function(_aida_c03_validate_raw_windows_path_shape",
		"input_path MATCHES \"\\\\\\\\\"",
		"NOT input_path MATCHES \"^[A-Z]:/\"",
		"input_path MATCHES \"//\"",
		"input_path MATCHES \"(^|/)\\\\.(/|$)\"",
		"input_path MATCHES \"(^|/)[^/]*[. ](/|$)\"",
		"input_path MATCHES \"[^ -~]\"",
		"file(REAL_PATH \"${input_path}\" _aida_c03_real_path)",
		"if(NOT input_path STREQUAL _aida_c03_real_path)",
		"IS_SYMLINK \"${input_path}\"",
		"file(SHA256 \"${input_path}\" _aida_c03_sha256)",
		"function(aida_c03_validate_no_reparse_chain",
		"COMMAND \"${powershell_executable}\"",
		"-File \"${policy_script}\" -Path \"${input_path}\"",
		"function(aida_c03_require_detached_roots",
		"file(REAL_PATH \"$ENV{TEMP}\" _aida_c03_temp_root)",
		"cmake_path(IS_PREFIX _aida_c03_temp_root",
		"stage roots must remain outside TEMP"})
		require_contains(path_policy, token,
			"canonical CMake path identity, reparse, and detached-root policy");
	for (const auto token : std::array<std::string_view, 12>{
		"CreateFileW", "GetFileInformationByHandleEx", "GetFinalPathNameByHandleW",
		"0x02200000", "AIDA_C03_PATH_IDENTITY_REPARSE",
		"AIDA_C03_PATH_IDENTITY_CASE", "[StringComparison]::Ordinal",
		"$Path.Length -gt 32767", "$Path.Contains('\\')", "$Path.Contains('//')",
		"$segment.EndsWith('.', [StringComparison]::Ordinal)",
		"$segment.EndsWith(' ', [StringComparison]::Ordinal)"})
		require_contains(path_identity, token,
			"handle-walk path identity policy");
	for (const auto token : std::array<std::string_view, 8>{
		"AIDA_C03_VALIDATED_PYTHON_EXECUTABLE",
		"AIDA_C03_VALIDATED_POWERSHELL_EXECUTABLE",
		"_aida_c03_package_require_python(_aida_c03_python)",
		"COMMAND \"${_aida_c03_python}\"",
		"aida_c03_require_detached_roots(",
		"aida_c03_validate_no_reparse_chain(",
		"_aida_c03_validate_raw_windows_path_shape(",
		"StageCustomerPackage"})
		require_contains(package_integration, token,
			"validated package tool and detached distribution policy");
	require_exact_count(package_integration, "COMMAND \"${_aida_c03_python}\"", 8,
		"validated Python package command inventory");
	require_absent(package_integration, "COMMAND \"${Python3_EXECUTABLE}\"",
		"raw Python package command absence");
	require_absent(package_integration, "find_program(",
		"unvalidated package interpreter discovery absence");

	const std::array<std::string_view, 11> authority_inputs = {
		"tools/c03_authority/verify_authority_surface_ledger.py",
		"tools/c03_authority/authority_surface_ledger.json",
		"tools/generate_ida_mcp_contracts/generate_ida_mcp_contracts.py",
		"src/standalone/tests/analysis_workspace/generate_surface_manifest.ps1",
		"src/standalone/tests/analysis_workspace/standalone_surface_baseline.json",
		"src/standalone/tests/analysis_workspace/standalone_surface_final.json",
		"src/standalone/src/resources/mcp/ida_pro_mcp_2_0_0/contracts.json",
		"src/standalone/src/resources/mcp/ida_pro_mcp_2_0_0/effect_ledger.json",
		"src/standalone/src/resources/mcp/ida_pro_mcp_2_0_0/archive_manifest.json",
		"src/standalone/src/core/mcp/compat/ida_contracts_generated.hpp",
		"src/standalone/src/core/mcp/compat/ida_contracts_generated.cpp"
	};
	const auto authority_configuration = slice_between(cmake_manifest,
		"if(NOT Python3_Interpreter_FOUND OR NOT Python3_EXECUTABLE)",
		"set_property(GLOBAL PROPERTY AIDA_C03_MANIFEST_TARGETS",
		"authority configure and identity inputs");
	for (const auto token : std::array<std::string_view, 18>{
		"if(NOT Python3_Interpreter_FOUND OR NOT Python3_EXECUTABLE)",
		"_aida_python_sha256", "${Python3_EXECUTABLE}",
		"_aida_system_powershell_sha256",
		"${_aida_system_root}/System32/WindowsPowerShell/v1.0/powershell.exe",
		"set(_aida_authority_archive \"C:/Users/ruar1337/ida-pro-mcp.zip\")",
		"_aida_authority_archive_sha256",
		"3F7E7D9F534E3534C191D21251BBF0788DB14376C659488EA61681D48BC8D0F7",
		"set(_aida_authority_repository_files",
		"aida_c03_require_sources(\"authority and surface reproduction\"",
		"CMAKE_CONFIGURE_DEPENDS", "${_aida_python_executable}",
		"${_aida_system_powershell}", "${_aida_authority_archive}",
		"foreach(_aida_authority_file IN LISTS _aida_authority_repository_files)",
		"file(SHA256 \"${_aida_authority_file}\" _aida_authority_file_sha256)",
		"string(SHA256 _aida_authority_identity",
		"_aida_authority_identity_material"})
		require_contains(authority_configuration, token,
			"authority configure and hash identity contract");
	const auto authority_file_inventory = slice_between(authority_configuration,
		"set(_aida_authority_repository_files",
		"aida_c03_require_sources(\"authority and surface reproduction\"",
		"authority repository file inventory");
	for (const auto input : authority_inputs)
		require_exact_count(authority_file_inventory, input, 1,
			"authority repository file inventory");
	for (const auto input : std::array<std::string_view, 2>{
			"${AIDA_C03_PATH_POLICY_MODULE}", "${AIDA_C03_PATH_IDENTITY_POLICY}"})
		require_exact_count(authority_file_inventory, input, 1,
			"authority path-policy repository file inventory");
	const auto policy_runtime = slice_between(cmake_manifest,
		"set(_aida_policy_runtime", "foreach(_aida_relative IN LISTS _aida_policy_runtime)",
		"source policy staged runtime inventory");
	for (const auto input : authority_inputs)
		require_exact_count(policy_runtime, input, 1,
			"source policy authority runtime inventory");
	for (const auto input : std::array<std::string_view, 2>{
			"src/standalone/tests/c03/testlab_runtime/safe_headless_driver_bridge.cpp",
			"src/standalone/src/core/anti-tamper/self_guard.hpp"})
		require_exact_count(policy_runtime, input, 1,
			"source policy safe-headless link-boundary runtime inventory");
	for (const auto input : std::array<std::string_view, 12>{
		"CMakeLists.txt",
		"packaging/c03_distribution_manifest.ps1",
		"src/standalone/tools/c03_package_verifier/main.cpp",
		"src/standalone/tests/c03/package_distribution_policy/policy_stage_spec.json",
		"src/standalone/src/core/analysis/build_worker_packaging_integration.cpp",
		"src/standalone/tests/c03/build_packaging_integration_harness.cpp",
		"src/standalone/tests/c03/package_distribution_policy/package_distribution_policy_harness.ps1",
		"src/standalone/tests/c03/auth_browser_dispatch/auth_browser_dispatch_harness.hpp",
		"src/standalone/tests/c03/auth_browser_dispatch/auth_browser_dispatch_harness.cpp",
		"cmake/aida_c03_package_integration.cmake",
		"cmake/c03_safe_headless/package_policy_fixture/aida_c03_path_policy.cmake",
		"cmake/c03_safe_headless/package_policy_fixture/aida_c03_path_identity.ps1"})
		require_exact_count(policy_runtime, input, 1,
			"source policy package-boundary runtime inventory");
	const auto production_sources = slice_between(cmake_manifest,
		"set(AIDA_C03_PRODUCTION_STANDALONE_SOURCES",
		"list(REMOVE_DUPLICATES AIDA_C03_PRODUCTION_STANDALONE_SOURCES)",
		"C03 production source registration");
	const auto harness_support_sources = slice_between(cmake_manifest,
		"set(AIDA_C03_HARNESS_SUPPORT_SOURCES",
		"set(AIDA_C03_WORKSPACE_HARNESS_SUPPORT_SOURCES",
		"C03 harness support registration");
	const auto workspace_support_sources = slice_between(cmake_manifest,
		"set(AIDA_C03_WORKSPACE_HARNESS_SUPPORT_SOURCES",
		"function(aida_c03_require_sources",
		"C03 workspace harness support registration");
	const auto compiler_matrix_cm02 = slice_between(cmake_manifest,
		"set(AIDA_C03_COMPILER_MATRIX_CM_02",
		"set(AIDA_C03_COMPILER_MATRIX_CM_03",
		"C03 CM-02 compiler matrix");
	const auto compiler_matrix_cm06 = slice_between(cmake_manifest,
		"set(AIDA_C03_COMPILER_MATRIX_CM_06",
		"set(AIDA_C03_COMPILER_MATRIX_CM_07",
		"C03 CM-06 compiler matrix");
	const auto compiler_matrix_cm09 = slice_between(cmake_manifest,
		"set(AIDA_C03_COMPILER_MATRIX_CM_09",
		"set(AIDA_C03_COMPILER_MATRIX_CM_10",
		"C03 CM-09 compiler matrix");
	const auto compiler_matrix_cm11 = slice_between(cmake_manifest,
		"set(AIDA_C03_COMPILER_MATRIX_CM_11",
		"set(AIDA_C03_COMPILER_MATRIX_CM_12",
		"C03 CM-11 compiler matrix");
	const auto compiler_matrix_cm12 = slice_between(cmake_manifest,
		"set(AIDA_C03_COMPILER_MATRIX_CM_12",
		"set(AIDA_C03_COMPILER_MATRIX_CM_13",
		"C03 CM-12 compiler matrix");
	const auto compiler_matrix_cm15 = slice_between(cmake_manifest,
		"set(AIDA_C03_COMPILER_MATRIX_CM_15",
		"set(AIDA_C03_COMPILER_MATRIX_UNION)",
		"C03 CM-15 compiler matrix");
	const auto compiler_matrix_cm13 = slice_between(cmake_manifest,
		"set(AIDA_C03_COMPILER_MATRIX_CM_13",
		"set(AIDA_C03_COMPILER_MATRIX_CM_14",
		"C03 CM-13 compiler matrix");
	const auto compiler_matrix_cm14 = slice_between(cmake_manifest,
		"set(AIDA_C03_COMPILER_MATRIX_CM_14",
		"set(AIDA_C03_COMPILER_MATRIX_CM_15",
		"C03 CM-14 compiler matrix");
	const auto runtime_exclusions = slice_between(cmake_manifest,
		"list(REMOVE_ITEM _aida_runtime_sources",
		"list(REMOVE_DUPLICATES _aida_runtime_sources)",
		"safe-headless runtime exclusion graph");
	const auto runtime_target = slice_between(cmake_manifest,
		"list(REMOVE_ITEM _aida_runtime_sources",
		"add_library(aida_c03_auth_preview_implementation STATIC",
		"safe-headless runtime production closure");
	for (const auto input : std::array<std::string_view, 9>{
			"aida_pretty_xml_encode.cpp", "aida_function_db.cpp", "aida_arch_map.cpp",
			"aida_load_image.cpp", "aida_pcode_fixup.cpp", "aida_print_c.cpp",
			"aida_scope.cpp", "aida_architecture.cpp", "aida_code_xml_parse.cpp"}) {
		require_exact_count(production_sources, input, 1,
			"Ghidra adapter production source closure");
		require_exact_count(compiler_matrix_cm06, input, 1,
			"Ghidra adapter CM-06 coverage");
	}
	for (const auto input : std::array<std::string_view, 6>{
			"ida_compat_read.cpp", "ida_compat_mut.cpp", "calculator_tool.cpp",
			"schema_validator.cpp", "mcp_standalone.cpp", "mcp_standalone_tools.cpp"}) {
		require_exact_count(production_sources, input, 1,
			"MCP production backend source closure");
		require_exact_count(compiler_matrix_cm11, input, 1,
			"MCP production backend CM-11 coverage");
	}
	for (const auto input : std::array<std::string_view, 4>{
			"core/network/burp/camoufox_bridge.cpp",
			"core/runtime/standalone_license.cpp",
			"src/shared/hardware_id/hardware_id_v2.cpp",
			"src/shared/telemetry/telemetry_client.cpp"}) {
		require_exact_count(production_sources, input, 1,
			"security and browser production source closure");
		require_exact_count(compiler_matrix_cm15, input, 1,
			"security and browser CM-15 coverage");
	}
	require_exact_count(production_sources, "core/analysis/pdb_downloader.cpp", 1,
		"PDB production source closure");
	require_exact_count(compiler_matrix_cm02, "core/analysis/pdb_downloader.cpp", 1,
		"PDB CM-02 coverage");
	require_exact_count(harness_support_sources,
		"testlab_runtime/safe_headless_driver_bridge.cpp", 1,
		"driverless safe-headless support registration");
	require_absent(production_sources, "safe_headless_driver_bridge.cpp",
		"driverless boundary in the production source graph");
	require_absent(workspace_support_sources, "safe_headless_driver_bridge.cpp",
		"driverless boundary in the workspace production graph");
	require_exact_count(compiler_matrix_cm14, "safe_headless_driver_bridge.cpp", 1,
		"driverless boundary CM-14 coverage");
	require_exact_count(compiler_matrix_cm12, "standalone_driver.cpp", 1,
		"real driver compiler-only coverage");
	require_exact_count(cmake_manifest, "standalone_driver.cpp", 1,
		"real driver exclusion from safe-headless link graph");
	require_exact_count(cmake_manifest, "safe_headless_driver_bridge.cpp", 3,
		"driverless boundary support matrix and scanner staging");
	for (const auto input : std::array<std::string_view, 2>{
			"decompiler_ui_integration.cpp", "workbench_shell_integration.cpp"}) {
		require_exact_count(production_sources, input, 1,
			"single-owner production integration source");
		require_absent(runtime_exclusions, input,
			"production integration removed from safe-headless runtime");
		require_exact_count(cmake_manifest, input, 2,
			"single runtime owner plus compiler-matrix occurrence");
	}
	require_exact_count(compiler_matrix_cm09, "decompiler_ui_integration.cpp", 1,
		"decompiler UI CM-09 coverage");
	require_exact_count(compiler_matrix_cm13, "workbench_shell_integration.cpp", 1,
		"workbench shell CM-13 coverage");
	for (const auto token : std::array<std::string_view, 7>{
			"aida_use_static_msvc_runtime(pcre2-8-static)",
			"AIDA_C03_SAFE_HEADLESS_RUNTIME=1", "aida_openssl_ssl_mt",
			"aida_openssl_crypto_mt", "LZMA_API_STATIC",
			"cabinet cfgmgr32 dnsapi iphlpapi ntdll Psapi setupapi version winhttp wintrust",
			"add_library(aida_c03_safe_headless_runtime STATIC"})
		require_exact_count(cmake_manifest, token, 1,
			"safe-headless static ABI and production library closure");
	require_exact_count(runtime_target, "AIDA_C03_SAFE_HEADLESS_RUNTIME=1", 1,
		"safe-headless runtime-only driver boundary definition");
	const auto benchmark_receipt_target = slice_between(cmake_manifest,
		"TARGET aida_c03_a06_benchmark_sla_receipt_harness",
		"set(_aida_dependency_runtime",
		"benchmark receipt target closure");
	require_exact_count(benchmark_receipt_target, "decompiler_quality_schema.cpp", 1,
		"benchmark receipt validation owner");
	const auto dependency_target = slice_between(cmake_manifest,
		"TARGET aida_c03_dependency_inventory_harness",
		"set(_aida_managed_runtime_source_root",
		"dependency inventory target closure");
	require_exact_count(dependency_target, "evidence_hash.cpp", 1,
		"dependency inventory evidence owner");
	const auto packaging_target = slice_between(cmake_manifest,
		"TARGET aida_c03_build_packaging_integration_harness",
		"TARGET aida_c03_surface_reconciliation_harness",
		"build packaging target closure");
	require_exact_count(packaging_target, "evidence_hash.cpp", 1,
		"build packaging evidence owner");
	const auto testlab_target = slice_between(cmake_manifest,
		"TARGET aida_c03_testlab_runtime_integration_harness",
		"TARGET aida_c03_b14_native_worker_containment_harness",
		"Test Lab direct target closure");
	require_exact_count(testlab_target, "testlab_runtime/result_adapter.cpp", 1,
		"Test Lab result envelope owner");
	const auto benchmark_target = slice_between(cmake_manifest,
		"TARGET aida_c03_analysis_benchmark_harness",
		"set_tests_properties(aida_c03_analysis_benchmark_harness PROPERTIES",
		"analysis benchmark direct target closure");
	require_exact_count(benchmark_target, "decompiler_quality_schema.cpp", 1,
		"analysis benchmark validation owner");
	const auto anti_tamper_target = slice_between(cmake_manifest,
		"TARGET aida_c03_anti_tamper_integrity_harness",
		"get_property(_aida_manifest_targets GLOBAL PROPERTY",
		"anti-tamper source target closure");
	for (const auto input : std::array<std::string_view, 5>{
			"anti_tamper_integrity_harness.cpp", "self_guard_policy_cases.cpp",
			"prologue_policy_cases.cpp", "dma_policy_cases.cpp",
			"passive_probe_policy_cases.cpp"})
		require_exact_count(anti_tamper_target, input, 1,
			"anti-tamper ordinary translation-unit registration");
	require_absent(anti_tamper_target, "UNITY_BUILD",
		"anti-tamper unity-build ODR workaround");
	for (const auto input : std::array<std::string_view, 6>{
			"core/auth/auth_store.cpp", "core/auth/auth_http.cpp",
			"core/auth/auth_codex.cpp", "core/auth/auth_copilot.cpp",
			"core/auth/auth_claude_code.cpp", "core/ai/provider_catalog.cpp"}) {
		require_exact_count(production_sources, input, 1,
			"normal auth implementation source registration");
		require_exact_count(compiler_matrix_cm15, input, 1,
			"normal and preview auth CM-15 translation-unit coverage");
	}
	for (const auto token : std::array<std::string_view, 8>{
			"set(_aida_auth_implementation_sources",
			"add_library(aida_c03_auth_preview_implementation STATIC",
			"AIDA_IMGUI_STUDIO_PREVIEW=1",
			"AIDA_C03_IMPLEMENTATION_VARIANT \"preview\"",
			"AIDA_C03_AUTH_IMPLEMENTATION_VARIANT \"normal\"",
			"NO_SHARED_RUNTIME",
			"TARGET aida_c03_auth_browser_dispatch_preview_harness",
			"LINK_LIBRARIES aida_c03_auth_preview_implementation"})
		require_contains(cmake_manifest, token,
			"independent normal and preview auth implementation graph");
	for (const auto input : std::array<std::string_view, 5>{
			"core/debugger/debugger_interaction_context.cpp",
			"core/ui/application_action_registry.cpp",
			"core/ui/application_ui_runtime.cpp",
			"core/ui/analysis_context_menu.cpp",
			"core/ui/imgui_capability_guard.cpp"}) {
		require_exact_count(production_sources, input, 1,
			"C03 production integration source registration");
		require_exact_count(compiler_matrix_cm13, input, 1,
			"C03 production integration CM-13 coverage");
	}
	require_absent(production_sources, "surface_reconciliation.cpp",
		"application production source registration");
	require_exact_count(harness_support_sources, "surface_reconciliation.cpp", 1,
		"harness-only surface reconciliation support registration");
	require_exact_count(compiler_matrix_cm15, "surface_reconciliation.cpp", 1,
		"surface reconciliation CM-15 retention");
	for (const auto input : std::array<std::string_view, 15>{
		"tools/c03_package_verifier/main.cpp",
		"build_worker_packaging_integration.hpp",
		"build_worker_packaging_integration.cpp",
		"build_packaging_integration_harness.cpp",
		"testlab_runtime/source_policy_scanner.cpp",
		"auth_browser_dispatch/auth_browser_dispatch_harness.cpp",
		"cmake/aida_c03_dependencies.cmake",
		"cmake/aida_c03_package_integration.cmake",
		"${AIDA_C03_SAFE_HEADLESS_CMAKE_MODULE}",
		"${AIDA_C03_PATH_POLICY_MODULE}", "${AIDA_C03_PATH_IDENTITY_POLICY}",
		"packaging/c03_distribution_manifest.ps1",
		"packaging/c03_distribution_fixture/path_byte_policy.json",
		"package_distribution_policy/package_distribution_policy_harness.ps1",
		"package_distribution_policy/policy_stage_spec.json"})
		require_exact_count(compiler_matrix_cm15, input, 1,
			"package policy CM-15 graph coverage");
	require_exact_count(cmake_manifest, "surface_reconciliation.cpp", 2,
		"surface reconciliation harness-only source classification");
	for (const auto target : std::array<std::string_view, 8>{
		"TARGET aida_c03_a00_authority_surface_harness",
		"TARGET aida_c03_c08_c19_mcp_compatibility_harness",
		"TARGET aida_c03_surface_reconciliation_harness",
		"TARGET aida_c03_source_policy_scanner",
		"TARGET aida_c03_mcp_production_core_harness",
		"TARGET aida_c03_auth_browser_dispatch_harness",
		"TARGET aida_c03_auth_browser_dispatch_preview_harness",
		"TARGET aida_c03_a06_decompiler_quality_scorer_harness"})
		require_exact_count(cmake_manifest, target, 1,
			"safe-headless canonical target registration");
	const auto preview_auth_registration = slice_between(cmake_manifest,
		"TARGET aida_c03_auth_browser_dispatch_preview_harness",
		"TARGET aida_c03_fixture_materializer_direct",
		"preview auth browser safe-headless registration");
	for (const auto token : std::array<std::string_view, 4>{
			"PACKAGE D08 TIMEOUT 300",
			"auth_browser_dispatch/auth_browser_dispatch_harness.cpp",
			"COMPILE_DEFINITIONS AIDA_IMGUI_STUDIO_PREVIEW=1",
			"TARGET aida_c03_auth_browser_dispatch_preview_harness"})
		require_exact_count(preview_auth_registration, token, 1,
			"preview auth browser exact target source and definition");
	const auto package_policy_test = slice_between(cmake_manifest,
		"add_test(NAME aida_c03_package_distribution_policy",
		"get_property(_aida_compiler_harness_inputs",
		"package distribution executable parity fixture registration");
	for (const auto token : std::array<std::string_view, 15>{
		"add_test(NAME aida_c03_package_distribution_policy",
		"COMMAND \"${_aida_system_powershell}\"",
		"package_distribution_policy_harness.ps1",
		"-Producer \"${CMAKE_SOURCE_DIR}/packaging/c03_distribution_manifest.ps1\"",
		"-ContractVerifier \"$<TARGET_FILE:aida_c03_build_packaging_integration_harness>\"",
		"-ProductionVerifier \"$<TARGET_FILE:aida_c03_package_verifier>\"",
		"-StageSpec \"${AIDA_C03_TEST_ROOT}/package_distribution_policy/policy_stage_spec.json\"",
		"-PathBytePolicy \"${CMAKE_SOURCE_DIR}/packaging/c03_distribution_fixture/path_byte_policy.json\"",
		"-AuthorityLock \"${AIDA_C03_WORKER_MANIFEST_LOCK}\"",
		"-ProtectorTool \"$<TARGET_FILE:AiDAProtector>\"",
		"-ProtectorVerifier \"$<TARGET_FILE:AiDAProtectorVerify>\"",
		"-ScratchRoot \"${AIDA_C03_DEVELOPER_ROOT}/scratch/package-policy/$<CONFIG>\"",
		"TIMEOUT 1200",
		"LABELS \"c03;c03_safe_headless;safe-headless;package;distribution;policy\"",
		"RESOURCE_LOCK \"aida_c03_package_distribution_policy\""})
		require_exact_count(package_policy_test, token, 1,
			"package distribution executable parity fixture registration");
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
	for (const auto retired : std::array<std::string, 6>{
		std::string("src/standalone/tests/c03/driver_bridge_") + "stub.cpp",
		std::string("src/standalone/tests/c03/driver_bridge_") + "stub.hpp",
		std::string("src/standalone/tests/analysis_workspace/workspace_mcp_") + "harness.cpp",
		std::string("src/standalone/tests/c03/decompiler_provider_matrix/") + "main.cpp",
		std::string("src/standalone/tests/c03/decompiler_quality_scorer_harness_") + "main.cpp",
		std::string("cmake/c03_safe_headless/materialize_quality_") + "selftest.py"})
		require_absent(cmake_manifest, retired,
			"safe-headless retired source registration");
}

void verify_distribution_source_leak_policy(const std::string_view producer,
	const std::string_view verifier, const std::string_view harness,
	const std::string_view policy_harness, const std::string_view cmake_manifest,
	const std::string_view package_integration, const std::string_view root_cmake,
	const std::string_view package_verifier, const std::string_view dependency_cmake,
	const std::string_view path_byte_policy)
{
	constexpr std::string_view forbidden_extensions[]{
		".a", ".asm", ".bash", ".bat", ".c", ".c++", ".cc", ".cmake", ".cmd", ".cpp",
		".cppm", ".cs", ".csproj", ".cxx", ".def", ".exp", ".fs", ".fsproj", ".go",
		".gradle", ".h", ".hh", ".hpp", ".hxx", ".ilk", ".in", ".inc", ".inl", ".ipp",
		".ixx", ".java", ".kt", ".kts", ".lib", ".m", ".make", ".map", ".mk", ".mm",
		".natvis", ".nupkg", ".nuspec", ".obj", ".pdb", ".props", ".ps1", ".psd1",
		".psm1", ".pth", ".py", ".pyc", ".pyo", ".pyz", ".rc", ".rc2", ".rs", ".s",
		".sh", ".sln", ".snupkg", ".spec", ".swift", ".targets", ".tpp", ".vb",
		".vbproj", ".vcxproj", ".vcxproj.filters", ".whl", ".zig", ".zsh"
	};
	std::set<std::string> expected_extensions;
	for (const auto extension : forbidden_extensions)
		expected_extensions.emplace(extension);
	const auto producer_extensions = quoted_source_literals(slice_between(producer,
		"$script:ForbiddenCustomerExtensions", "$script:ForbiddenCustomerFileNames",
		"distribution producer extension policy"), '\'',
		"distribution producer extension policy");
	const auto verifier_extensions = quoted_source_literals(slice_between(verifier,
		"constexpr std::string_view forbidden_extensions[]{",
		"constexpr std::string_view forbidden_names[]{",
		"distribution verifier extension policy"), '"',
		"distribution verifier extension policy");
	const auto harness_extensions = quoted_source_literals(slice_between(harness,
		"constexpr std::string_view forbidden_extensions[]{",
		"constexpr std::string_view forbidden_paths[]{",
		"distribution harness extension cases"), '"',
		"distribution harness extension cases");
	require(producer_extensions == expected_extensions &&
		verifier_extensions == expected_extensions && harness_extensions == expected_extensions,
		"distribution source and script extension policy is exact across producer, verifier, and fixtures");
	for (const auto extension : forbidden_extensions) {
		require_contains(producer, "'" + std::string(extension) + "'",
			"distribution producer forbidden source and script extension inventory");
		require_contains(verifier, "\"" + std::string(extension) + "\"",
			"distribution verifier forbidden source and script extension inventory");
		require_contains(harness, "\"" + std::string(extension) + "\"",
			"distribution production-path forbidden extension fixtures");
	}
	const auto lowered_harness = ascii_lower(std::string(harness));
	const std::array<std::string_view, 8> forbidden_names{
		"build", "build.bazel", "cmakelists.txt", "gnumakefile", "makefile",
		"meson.build", "workspace", "workspace.bazel"};
	std::set<std::string> expected_names;
	for (const auto name : forbidden_names)
		expected_names.emplace(name);
	require(quoted_source_literals(slice_between(producer,
		"$script:ForbiddenCustomerFileNames", "$script:ForbiddenCustomerDirectoryNames",
		"distribution producer build-file policy"), '\'',
		"distribution producer build-file policy") == expected_names &&
		quoted_source_literals(slice_between(verifier,
			"constexpr std::string_view forbidden_names[]{",
			"constexpr std::string_view forbidden_directories[]{",
			"distribution verifier build-file policy"), '"',
			"distribution verifier build-file policy") == expected_names,
		"distribution forbidden build-file policy is exact across producer and verifier");
	for (const auto name : forbidden_names) {
		require_contains(producer, "'" + std::string(name) + "'",
			"distribution producer forbidden build-file inventory");
		require_contains(verifier, "\"" + std::string(name) + "\"",
			"distribution verifier forbidden build-file inventory");
		require_contains(lowered_harness, std::string(name),
			"distribution forbidden build-file production fixture");
	}
	const std::array<std::string_view, 8> forbidden_directories{
		"c03-safe-headless", "camoufox-reverse-mcp", "camoufox_reverse_mcp",
		"library-packs", "metadata", "packs", "sdk", "templates"};
	std::set<std::string> expected_directories;
	for (const auto directory : forbidden_directories)
		expected_directories.emplace(directory);
	require(quoted_source_literals(slice_between(producer,
		"$script:ForbiddenCustomerDirectoryNames",
		"$script:StockBrowserNames",
		"distribution producer forbidden directory policy"), '\'',
		"distribution producer forbidden directory policy") == expected_directories &&
		quoted_source_literals(slice_between(verifier,
			"constexpr std::string_view forbidden_directories[]{",
			"constexpr std::string_view stock_browsers[]{",
			"distribution verifier forbidden directory policy"), '"',
			"distribution verifier forbidden directory policy") == expected_directories,
		"distribution forbidden directory policy is exact across producer and verifier");
	for (const auto directory : forbidden_directories) {
		require_contains(producer, "'" + std::string(directory) + "'",
			"distribution producer forbidden directory inventory");
		require_contains(verifier, "\"" + std::string(directory) + "\"",
			"distribution verifier forbidden directory inventory");
		require_contains(lowered_harness, std::string(directory),
			"distribution forbidden directory production fixture");
	}
	for (const auto token : std::array<std::string_view, 14>{
		"function Test-ForbiddenCustomerRelativePath",
		"function Get-Utf8PathByteCount",
		"$script:ForbiddenCustomerExtensions",
		"$script:ForbiddenCustomerFileNames",
		"$script:ForbiddenCustomerDirectoryNames",
		"(Get-Utf8PathByteCount -Value $RelativePath) -gt $script:MaximumRelativePathBytes",
		"$code -lt 0x21 -or $code -gt 0x7e",
		"$character -in @('\\', ':', '<', '>', '\"', '|', '?', '*')",
		"$lower.IndexOf('.dist-info', [StringComparison]::Ordinal)",
		"$lower.IndexOf('.egg-info', [StringComparison]::Ordinal)",
		"-not (Test-AsciiAlphaNumeric -Character $lower[$after])",
		"Test-PolicyNameMatch -Segment $lower -Forbidden $name",
		"'stock-firefox', 'stock-firefox.exe'",
		"if (Test-ForbiddenCustomerRelativePath -RelativePath $RelativePath)"})
		require_contains(producer, token,
			"distribution producer fail-closed customer path policy");
	for (const auto token : std::array<std::string_view, 16>{
		"bool unexpected_customer_file(std::string_view relative)",
		"forbidden_extensions[]", "forbidden_names[]", "forbidden_directories[]",
		"bool safe_relative_path(std::string_view value)",
		"character < 0x21U || character > 0x7eU",
		"character == '\\\\'", "character == ':'", "part.back() == '.'",
		"!ascii_alphanumeric(segment[after])",
		"policy_name_match(segment, value)",
		".dist-info", ".egg-info", "stock-firefox.exe",
		"if (unexpected_customer_file(artifact.relative_path))",
		"if (unexpected_customer_file(text))"})
		require_contains(verifier, token,
			"distribution verifier fail-closed customer path policy");
	for (const auto token : std::array<std::string_view, 42>{
		"verify_utf8_path_policy_table();",
		"verify_utf8_path_budget_boundaries(fixture, integration, manifest_hash);",
		"verify_cancellation_deadline_policy(fixture, integration, manifest_hash);",
		"verify_allowed_customer_path_neighbors(fixture, integration);",
		"verify_forbidden_customer_path_policy(fixture, integration);",
		"verify_actual_path_stream_and_resource_policy(fixture, integration, manifest_hash);",
		"verify_immutable_generation_mutation_policy(fixture, integration, manifest_hash);",
		"verify_build_bound_link_graph_mutations(fixture, integration);",
		"package_verification_checkpoint_t::immutable_generation_captured",
		"package_verification_checkpoint_t::immutable_generation_precommit",
		"CreateFileMappingW", "MapViewOfFile", "FlushViewOfFile",
		"same-size mapped mutation escaped immutable-generation verification",
		"integration.verify_distribution_package(request_for(fixture, digest))",
		"nested/payload.CpP", "nested/payload.PS1.backup",
		"nested/payload.HPP_copy", "nested/payload.CMAKE-old",
		"nested/C03-SAFE-HEADLESS/bin/harness.exe",
		"c03-safe-headless/nested/HARNESS.CPP",
		"unlisted developer safe-headless source payload was accepted",
		"reject(std::string(32769, 'x'))",
		"resources/runtime-policy.json", "resources/runtime-policy.sha256",
		"resources/LICENSE.txt", "resources/NOTICE.md",
		"CreateSymbolicLinkW", "named-stream package artifact was accepted",
		"maximum_inventory_path_bytes = 1",
		"repeated production verifier results are not deterministic",
		"payload-\\xce\\x94.bin",
		"production-link-graph", "aida.c03.production-link-graph.v3",
		"strict_roots", "host_direct_edges", "host_preexisting_exemptions",
		"AiDAStandalone|LINK_LIBRARIES|unicorn",
		"strict-link-forbidden.json", "host-link-forbidden.json",
		"hardlink_forbidden", "verified package contract fixtures"})
		require_contains(harness, token,
			"distribution production-shaped package-boundary fixtures");
	for (const auto token : std::array<std::string_view, 40>{
		"Invoke-Child -Executable $ContractVerifier",
		"Invoke-Child -Executable $ProductionVerifier",
		"producer policy report is not repeatable",
		"AIDA_C03_PACKAGE_POLICY_RAW_ABSOLUTE_PATH",
		"payload-' + [char]0x394 + '.bin",
		"payload`t.bin", "payload.cpp.backup", "CMakeLists.TxT", "SDK/runtime.dll",
		"$adsFile + ':aida-policy'", "AIDA_C03_PACKAGE_POLICY_NAMED_STREAM_FORBIDDEN",
		"FixtureMaximumFiles", "FixtureMaximumDirectories", "FixtureMaximumEntries",
		"FixtureMaximumDepth", "FixtureMaximumRelativePathBytes",
		"FixtureMaximumInventoryPathBytes",
		"FixtureMaximumEntryBytes", "FixtureMaximumAggregateBytes",
		"New-Item -ItemType HardLink",
		"New-Item -ItemType Junction", "New-Item -ItemType SymbolicLink",
		"-StageCustomerPackage", "-StagePolicyFixture",
		"Read-CompleteGeneration -PointerPath $generationPointer",
		".generation-pointer.json",
		"foreach ($checkpoint in @('prepared', 'package-ready', 'evidence-ready', 'before-commit'))",
		"FixturePublicationFailure", "after-commit",
		"Start-Process -FilePath $PowerShellExecutable",
		"$readerGenerations", "--generation-pointer",
		"inspect-generation",
		"external-authority-not-provisioned/signer-policy.json",
		"customer restage atomicity or repeatability violated the detached source boundary",
		"AIDA_C03_PACKAGE_POLICY_CANONICAL_PATH_OPEN",
		"failed stage prevalidation changed the prior complete generation",
		"concurrent readers observed a torn or mixed generation",
		"$concurrentFinal.id -cne $postCommitGeneration.id",
		"@($pathPolicy.cases).Count -eq 12"})
		require_contains(policy_harness, token,
			"executable package producer and verifier parity fixtures");
	for (const auto token : std::array<std::string_view, 14>{
			"New-PePostProcessFixture", "inspect-pe-post-process",
			"'coff-symbols'", "'rich'", "'dans'", "'codeview-path'",
			"'malformed-debug'", "'truncated-debug'",
			"run-signing-provider", "signing authority point-of-use identity mismatch",
			"immutable signing provider returned failure", "provider-hardlink",
			"policy-hardlink", "policy-reparse"})
		require_contains(policy_harness, token,
			"artifact measurement and point-of-use signing authority negative fixtures");
	for (const auto token : std::array<std::string_view, 5>{
			"generation-identity-hardlink-", "customer-anchor-reparse",
			"evidence-root-reparse", "stage-owner-reparse",
			"path component identity is invalid"})
		require_contains(policy_harness, token,
			"detached authority component and evidence identity negative fixtures");
	for (const auto token : std::array<std::string_view, 8>{
			"unauthorized_signer_thumbprint_sha256", "signature_verifier_result",
			"trusted_timestamp", "unauthorized_actual_signer_thumbprint_sha256",
			"signer_receipt_identity_mismatch", "zero trusted timestamp",
			"mismatched authorized actual signer",
			"invalid-signature-timestamp-status.json"})
		require_contains(harness, token,
			"signer receipt and timestamp semantic negative fixtures");
	for (const auto token : std::array<std::string_view, 23>{
		"[Collections.Generic.Queue[object]]::new()",
		"Sort-Object -Property relative_path -CaseSensitive",
		"$script:MaximumPackageFiles = 250000",
		"$script:MaximumPackageDirectories = 65536",
		"$script:MaximumPackageEntries = 300000",
		"$script:MaximumPackageDepth = 64",
		"$script:MaximumRelativePathBytes = 32768",
		"$script:MaximumInventoryPathBytes = [Int64]268435456",
		"RESOURCE_PATH_BUFFER_LIMIT", "Assert-NoNamedStreams", "Get-Utf8PathByteCount",
		"Assert-SingleLinkFile", "NumberOfLinks", "HARDLINK_FORBIDDEN",
		"Get-DirectoryIdentity", "DIRECTORY_CYCLE", "DUPLICATE_CASE_PATH",
		"Stage-SanitizedCustomerPackage", "[IO.File]::Copy",
		"STAGE_COPY_IDENTITY", "STAGE_EXACT_INVENTORY",
		"Get-ExactExistingPath", "GetFinalPathNameByHandleW"})
		require_contains(producer, token,
			"bounded deterministic copy-only package producer policy");
	const auto customer_stage = slice_between(producer,
		"function Stage-SanitizedCustomerPackage",
		"function Start-ImmutableGeneration",
		"sanitized customer stage implementation");
	require_ordered(customer_stage, {
		"Read-StrictJson -Path $SpecificationPath",
		"$copyPlan = [Collections.Generic.List[object]]::new()",
		"Get-LockedIdentity -Path $sourcePath",
		"'.aida-c03-candidate-'",
		"[IO.File]::Copy([string]$copyEntry.source_path, $candidatePath, $false)",
		"Get-BoundedTreeInventory -Root $candidateFull",
		"Assert-ImmutableGeneration",
		"$retainCandidate = $true",
		"candidate_identity = $candidateDirectoryIdentity"
	}, "prevalidated deferred customer generation ordering");
	require_absent(customer_stage, "Publish-PackageDirectory",
		"legacy non-generation customer directory publication");
	require_absent(customer_stage, "$DeferPublication",
		"optional non-generation customer publication mode");
	require_absent(customer_stage, "[IO.Directory]::Delete($destinationFull, $true)",
		"destructive customer destination replacement");
	const auto complete_generation = slice_between(producer,
		"function Publish-CompleteGeneration",
		"function Stage-SanitizedCustomerPackage",
		"complete package and evidence publication transaction");
	require_ordered(complete_generation, {
		"$publicationLock = [AidaC03PackageNative]::CreateFileW(",
		"Recover-PublicationJournal -Path $publicationJournalPath",
		"Remove-OwnedGenerationDirectory -Path $stalePackage",
		"Write-PublicationJournal -Path $publicationJournalPath -Value $journal",
		"Invoke-PublicationCheckpoint -Name 'prepared'",
		"[IO.Directory]::Move([string]$Stage.candidate_path, $packageGeneration)",
		"Set-ImmutableGenerationExpectedPathPrefix -OldRoot ([string]$Stage.candidate_path) -NewRoot $packageGeneration",
		"Get-BoundedTreeInventory -Root $packageGeneration",
		"Invoke-PublicationCheckpoint -Name 'package-ready'",
		"[IO.Directory]::Move($EvidenceCandidate, $evidenceGeneration)",
		"Set-ImmutableGenerationExpectedPathPrefix -OldRoot $EvidenceCandidate -NewRoot $evidenceGeneration",
		"Assert-ImmutableGeneration",
		"Invoke-PublicationCheckpoint -Name 'before-commit'",
		"Write-AtomicBytes -Path $pointerPath -Bytes $pointerBytes -Replace:$Replace",
		"$pointerCommitted = $true"
	}, "atomic complete-generation pointer publication ordering");
	for (const auto token : std::array<std::string_view, 19>{
		"aida.c03.complete-generation-pointer", ".aida-c03-generation-",
		".aida-c03-publication.lock", ".aida-c03-publication-journal.json",
		"aida.c03.publication-journal", "Recover-PublicationJournal",
		"Write-PublicationJournal", "if (-not $pointerCommitted)",
		"[IO.Directory]::Move($evidenceGeneration, $EvidenceCandidate)",
		"Set-ImmutableGenerationExpectedPathPrefix -OldRoot $evidenceGeneration -NewRoot $EvidenceCandidate",
		"[IO.Directory]::Move($packageGeneration, [string]$Stage.candidate_path)",
		"Set-ImmutableGenerationExpectedPathPrefix -OldRoot $packageGeneration -NewRoot ([string]$Stage.candidate_path)",
		"CloseHandle($publicationLock)", "FixturePublicationFailure",
		"FixturePublicationTermination", "Stop-Process -Id $PID -Force",
		"prepared", "evidence-ready", "after-commit"})
		require_contains(complete_generation, token,
			"complete generation cleanup rollback and failure policy");
	require_absent(complete_generation, "[IO.File]::Move($ManifestCandidate, $ManifestDestination)",
		"sequential manifest publication");
	require_absent(complete_generation, "[IO.File]::Move($DigestCandidate, $DigestDestination)",
		"sequential digest publication");
	for (const auto token : std::array<std::string_view, 25>{
		"Start-ImmutableGeneration", "Stop-ImmutableGeneration",
		"function Get-LockedIdentity", "function Get-LockedBytes",
		"function Get-LockedFinalPath", "function Assert-ImmutableGeneration",
		"Get-LockedFinalPath -Entry $entry",
		"STAGE_OWNERSHIP", "STAGE_ROOT_OVERLAP", "STAGE_SOURCE_OVERLAP",
		"foreach ($ownedRoot in @($productionCandidateAnchor, $stageAnchor, $evidenceRootPath))",
		"Get-Utf8PathByteCount -Value $relative",
		"Get-Utf8PathByteCount -Value $entryFull",
		"Set-ImmutableGenerationExpectedPathPrefix",
		"expected_final_path", "HARDLINK_FORBIDDEN",
		"EVIDENCE_GENERATION_LIMIT", "function Test-GenerationReclaimable",
		"EVIDENCE_GENERATION_RECLAIM",
		"$fixtureDigestPath = $fixtureReportPath + '.sha256'",
		"Publish-CompleteGeneration -Stage $productionStage",
		"-EvidencePublicationAnchor $evidencePublicationAnchor",
		".generation-pointer.json", "-Transient -CaptureBytes",
		"$journalFinal = Get-LockedIdentity"})
		require_contains(producer, token,
			"immutable UTF-8 package and fixture generation contract");
	for (const auto token : std::array<std::string_view, 17>{
		"std::queue<pending_directory_t>", "std::vector<discovered_entry_t>",
		"std::sort(discovered.begin(), discovered.end()",
		"maximum_total_entry_count", "maximum_directory_count", "maximum_depth",
		"maximum_relative_path_bytes", "maximum_inventory_path_bytes",
		"maximum_artifact_bytes", "maximum_total_artifact_bytes",
		"verify_stream_inventory", "directory_identities", "directory_cycle",
		"FILE_FLAG_OPEN_REPARSE_POINT", "GetFinalPathNameByHandleW",
		"case-colliding path", "inventory_path_bytes"})
		require_contains(verifier, token,
			"bounded deterministic package verifier policy");
	for (const auto token : std::array<std::string_view, 11>{
		"immutable_generation_context_t", "immutable_generation_scope_t",
		"rehash_locked_generation_file", "immutable_generation_hash",
		"package_verification_checkpoint_t::immutable_generation_captured",
		"package_verification_checkpoint_t::immutable_generation_precommit",
		"revalidate_immutable_generation(immutable_generation)",
		"auto final_inventory = enumerate_package_tree(package_root, request)",
		"relative.generic_u8string()", "iterator->path().generic_u8string()",
		"final_inventory.value().path_bytes != bounded_inventory.value().path_bytes"})
		require_contains(verifier, token,
			"immutable UTF-8 production package verification contract");
	for (const auto token : std::array<std::string_view, 24>{
		"hardlink_forbidden", "nNumberOfLinks", "poll_verification_control",
		"deadline_exceeded", "cancelled", "request.protector_verifier",
		"request.signature_verifier", "direct_protector_verifier",
		"signer_policy_sha256", "signing_provider_sha256",
		"production-link-graph", "build_evidence",
		"aida.c03.production-link-graph.v3", "link_denylist",
		"strict_roots", "strict_targets", "strict_edges",
		"host_direct_edges", "host_preexisting_exemptions",
		"AiDAStandalone|LINK_LIBRARIES|unicorn",
		"AiDAStandalone", "forbidden_link_token",
		"production_link_graph_verified",
		"result.deny_link_policy = production_link_graph_verified"})
		require_contains(verifier, token,
			"hardlink cancellation signer protector and deny-link verification contract");
	const auto root_contract = slice_between(cmake_manifest,
		"if(NOT DEFINED ENV{LOCALAPPDATA}",
		"set(AIDA_C03_SAFE_HEADLESS_INVENTORY",
		"detached application developer and customer root contract");
	for (const auto token : std::array<std::string_view, 15>{
		"if(NOT DEFINED ENV{LOCALAPPDATA} OR NOT IS_ABSOLUTE \"$ENV{LOCALAPPDATA}\")",
		"string(SHA256 AIDA_C03_STAGE_AUTHORITY_ID",
		"${_aida_c03_local_app_data}/AiDA/C03/${AIDA_C03_STAGE_AUTHORITY_ID}",
		"set(AIDA_C03_APPLICATION_BUILD_ROOT \"${AIDA_C03_STAGE_OWNER_ROOT}/application\")",
		"set(AIDA_C03_DEVELOPER_ROOT \"${AIDA_C03_STAGE_OWNER_ROOT}/developer\")",
		"set(AIDA_C03_CUSTOMER_STAGE_ANCHOR \"${AIDA_C03_STAGE_OWNER_ROOT}/customer\")",
		"set(AIDA_C03_DISTRIBUTION_EVIDENCE_ROOT \"${AIDA_C03_STAGE_OWNER_ROOT}/evidence\")",
		".aida-c03-stage-owner.json",
		"external stage root is owned by a different source/binary authority",
		"file(MAKE_DIRECTORY",
		"\"${AIDA_C03_DEVELOPER_ROOT}\"",
		"\"${AIDA_C03_CUSTOMER_STAGE_ANCHOR}\"",
		"aida_c03_require_detached_roots(",
		"set(AIDA_C03_SAFE_HEADLESS_STAGE_ROOT \"${AIDA_C03_DEVELOPER_ROOT}/suite/$<CONFIG>\")",
		"set(AIDA_C03_CUSTOMER_PACKAGE_ROOT \"${AIDA_C03_CUSTOMER_STAGE_ANCHOR}/$<CONFIG>\")"})
		require_contains(root_contract, token,
			"detached sibling stage root policy");
	require_absent(root_contract, "$ENV{TEMP}",
		"TEMP-backed developer or customer stage root");
	for (const auto token : std::array<std::string_view, 10>{
		"APPLICATION_ROOT \"${AIDA_C03_APPLICATION_BUILD_ROOT}\"",
		"SOURCE_ROOT \"$<TARGET_FILE_DIR:${application_target}>\"",
		"DEVELOPER_ROOT \"${AIDA_C03_DEVELOPER_ROOT}\"",
		"CUSTOMER_STAGE_ANCHOR \"${AIDA_C03_CUSTOMER_STAGE_ANCHOR}\"",
		"EVIDENCE_ROOT \"${AIDA_C03_DISTRIBUTION_EVIDENCE_ROOT}\"",
		"STAGE_OWNER_ROOT \"${AIDA_C03_STAGE_OWNER_ROOT}\"",
		"PACKAGE_ROOT \"${AIDA_C03_CUSTOMER_PACKAGE_ROOT}\"",
		"file(MAKE_DIRECTORY \"${_aida_c03_distribution_output_root}\")",
		"PACKAGE_VERIFIER_TARGET aida_c03_package_verifier",
		"aida_c03_validate_no_reparse_chain("})
		require_contains(cmake_manifest, token,
			"copy-only detached distribution registration");
	for (const auto token : std::array<std::string_view, 19>{
		"-StageCustomerPackage", "-SourceRoot", "-ApplicationStageAnchor",
		"-CustomerStageAnchor", "-EvidenceRoot", "-StageOwnerRoot",
		"COMMAND \"$<TARGET_FILE:${_aida_c03_PACKAGE_VERIFIER_TARGET}>\" verify-package",
		"--generation-pointer", "--customer-stage-anchor", "--evidence-root",
		"--stage-owner-root", "--authority-lock", "--protector-verifier",
		"--signature-verifier", "--signer-policy", "--expected-signer-policy-sha256",
		"--signing-provider", "--expected-signing-provider-sha256",
		"--deadline-ms 900000"})
		require_contains(package_integration, token,
			"detached generation and strict production verifier command");
	for (const auto token : std::array<std::string_view, 36>{
		"int emit_receipts(const parsed_arguments_t& parsed)",
		"int inspect_generation(const parsed_arguments_t& parsed)",
		"int verify_package(const parsed_arguments_t& parsed)",
		"arguments.mode == L\"inspect-generation\"",
		"lock_file(arguments.at(L\"artifact\")",
		"verifier::verify_report(artifact.path.string(), profile)",
		"verify_authenticode(artifact.path)", "WTD_CACHE_ONLY_URL_RETRIEVAL",
		"WTD_REVOKE_WHOLECHAIN", "WTHelperProvDataFromStateData",
		"WTHelperGetProvSignerFromChain", "WTHelperGetProvCertFromChain",
		"wintrust_provider_counter_signer", "measure_pe_post_process",
		"FlushFileBuffers", "ReplaceFileW", "MOVEFILE_WRITE_THROUGH",
		"verifier.verify_distribution_package(request)",
		"request.verification_checkpoint", "fixed_time_equal(file.sha256, observed.sha256)",
		"load_complete_generation", "aida.c03.complete-generation-pointer",
		"FILE_SHARE_DELETE", "replacement_tolerant", "generation.package_root",
		"publication_lock_path", "FILE_READ_ATTRIBUTES", "lock_directory",
		"strict_descendant",
		"generation.manifest_path", "generation.manifest_sha256",
		"request.protector_verifier", "verifier::verify_report(path.string(), profile)",
		"request.signature_verifier", "authorized_signers", "cancellation_requested"})
		require_contains(package_verifier, token,
			"strict production package verifier and receipt producer");
	for (const auto token : std::array<std::string_view, 18>{
			"arguments.mode == L\"inspect-pe-post-process\"",
			"arguments.mode == L\"run-signing-provider\"",
			"WTHelperGetProvSignerFromChain(provider, 0, TRUE, index)",
			"counter_signer->sftVerifyAsOf", "counter_signer->pChainContext",
			"CERT_CONFIDENCE_SIG", "CertVerifyTimeValidity",
			"coff_symbol_table_pointer", "coff_symbol_count",
			"unscrubbed_debug_paths", "rich_signature_count",
			"dans_signature_count", "final PE artifact failed measured scrub policy",
			"copy_locked_authority", "immutable signing authority copy identity mismatch",
			"CreateProcessW(immutable_provider.path.c_str()",
			"revalidate(immutable_provider)", "revalidate(immutable_policy)"})
		require_contains(package_verifier, token,
			"provider-backed timestamp PE measurement and immutable signer execution");
	require_absent(package_verifier, "szOID_RSA_counterSign",
		"raw Authenticode countersignature OID inference");
	require_absent(package_verifier, "szOID_RFC3161_counterSign",
		"raw RFC3161 countersignature OID inference");
	for (const auto token : std::array<std::string_view, 24>{
		"AIDA_C03_SIGNER_POLICY_FILE", "AIDA_C03_SIGNING_PROVIDER",
		"AIDA_C03_SIGNING_PROVIDER_SHA256", "AIDA_C03_SIGNING_AUTHORITY_BLOCKER",
		"function(aida_c03_configure_signing_authority)",
		"aida.c03.authorized-signer-policy", "authorized_signer_thumbprints_sha256",
		"require_trusted_timestamp",
		"function(aida_c03_emit_production_link_graph_evidence output_path integration_host)",
		"aida_c03_reject_forbidden_target_links(${_aida_c03_strict_roots})",
		"LINK_LIBRARIES", "INTERFACE_LINK_LIBRARIES",
		"IMPORTED_LINK_DEPENDENT_LIBRARIES_RELEASE",
		"aida.c03.production-link-graph.v3", "AiDAStandalone",
		"_aida_c03_host_exemptions", "AiDAStandalone|LINK_LIBRARIES|unicorn",
		"manifest_root_count",
		"AIDA_C03_LOCKED_PRODUCTION_LINK_DENYLIST", "AIDA_C03_PRODUCTION_LINK_DENY_TOKENS",
		"_aida_c03_namespaced_link_tokens", "_aida_c03_plain_link_tokens",
		"file(SHA256",
		"AIDA_C03_PRODUCTION_LINK_GRAPH_EVIDENCE_SHA256"})
		require_contains(dependency_cmake, token,
			"production build-bound deny-link evidence generator");
	for (const auto token : std::array<std::string_view, 10>{
		"aida_c03_emit_production_link_graph_evidence(",
		"AiDAStandalone", "aida_c03_b14_native_decompiler_worker",
		"aida_c03_package_verifier",
		"aida_c03_production_link_graph_package_evidence",
		"deps/evidence/production-link-graph.json",
		"add_dependencies(aida_c03_distribution_manifest",
		"AIDA_C03_PRODUCTION_LINK_GRAPH_EVIDENCE",
		"production-target-link-graph-evidence-v3",
		"copy_if_different"})
		require_contains(root_cmake, token,
			"production target graph distribution binding");
	const auto standalone_link_binding = slice_between(root_cmake,
		"target_link_directories(AiDAStandalone PRIVATE",
		"set_target_properties(AiDAStandalone PROPERTIES",
		"final standalone link and C03 evidence binding");
	require_ordered(standalone_link_binding, {
		"target_link_libraries(AiDAStandalone PRIVATE",
		"target_link_libraries(AiDAStandalone PRIVATE aida_hardening)",
		"aida_c03_emit_production_link_graph_evidence(",
		"add_custom_target(aida_c03_production_link_graph_package_evidence"
	}, "post-link C03 graph evidence generation");
	require_contains(dependency_cmake,
		"string(JOIN \"\\\",\\\"\" _aida_c03_denylist ${AIDA_C03_PRODUCTION_LINK_DENY_TOKENS})",
		"complete production graph deny-list evidence");
	require_contains(verifier, "\"lief\", \"lmdb\", \"unicorn\", \"remill\"",
		"complete production graph deny-list enforcement");
	require_contains(harness, "unicorn_static",
		"forbidden underscore-suffix build-bound link fixture");
	for (const auto token : std::array<std::string_view, 8>{
		"aida.c03.utf8-path-byte-policy.v1", "maximum_relative_path_bytes",
		"maximum_inventory_path_bytes", "customer_path_allowed",
		"utf8_bytes", "payload.cpp.backup", "CMakeLists.TxT", "cases"})
		require_contains(path_byte_policy, token,
			"canonical UTF-8 path byte policy table");
	for (const auto token : std::array<std::string_view, 17>{
		"add_custom_target(aida_c03_standalone_security_receipts",
		"COMMAND \"$<TARGET_FILE:aida_c03_package_verifier>\" emit-receipts",
		"_aida_c03_package_signing_step(",
		"--protector-profile \"standalone-no-imports\"",
		"--signer-policy \"${AIDA_C03_SIGNER_POLICY_FILE}\"",
		"--signing-provider \"${AIDA_C03_SIGNING_PROVIDER}\"",
		"--deadline-ms 900000",
		"standalone-protector-signature-receipts-v4",
		"standalone.protector.json", "standalone.signature.json",
		"DEPENDS AiDAStandaloneNoIATVerify AiDAProtector AiDAProtectorVerify",
		"AIDA_C03_FINAL_BYTE_ORDERING \"link;scrub;protect;direct-protector-verify;offline-wintrust-receipts\"",
		"aida_c03_b14_native_worker_package_manifest",
		"aida_c03_b16_managed_worker_package_manifest",
		"add_dependencies(aida_c03_distribution_manifest",
		"aida_c03_standalone_security_receipts",
		"AIDA_C03_STANDALONE_RECEIPT_TARGET aida_c03_standalone_security_receipts"})
		require_contains(root_cmake, token,
			"protected standalone and worker receipt dependency graph");
	const auto materializer_command = slice_between(cmake_manifest,
		"add_custom_command(OUTPUT \"${AIDA_C03_SAFE_HEADLESS_MANIFEST}\"",
		"add_custom_command(OUTPUT \"${AIDA_C03_SAFE_HEADLESS_DIGEST_HEADER}\"",
		"safe-headless manifest materializer command");
	require_exact_count(materializer_command,
		"COMMAND \"${_aida_python_executable}\" \"${AIDA_C03_SAFE_HEADLESS_MATERIALIZER}\"", 1,
		"safe-headless validated Python materializer command");
	require_absent(materializer_command, "${Python3_EXECUTABLE}",
		"safe-headless raw Python materializer command");
	const auto developer_manifest = slice_between(cmake_manifest,
		"add_custom_target(aida_c03_safe_headless_manifest",
		"add_custom_target(aida_c03_safe_headless_application_package",
		"safe-headless developer manifest identity");
	for (const auto token : std::array<std::string_view, 5>{
		"AIDA_C03_DEVELOPER_ONLY TRUE",
		"AIDA_C03_DEVELOPER_SUITE_OUTPUTS \"suite/$<CONFIG>/manifest.json;suite/$<CONFIG>/manifest.sha256\"",
		"${AIDA_C03_SAFE_HEADLESS_MANIFEST}", "${AIDA_C03_SAFE_HEADLESS_DIGEST}",
		"${AIDA_C03_SAFE_HEADLESS_DIGEST_HEADER}"})
		require_contains(developer_manifest, token,
			"developer-only safe-headless manifest and digest identity");
	require_absent(developer_manifest, "AIDA_C03_PACKAGE_OUTPUTS",
		"customer package output classification for developer safe-headless artifacts");
	const auto application_package = slice_between(cmake_manifest,
		"add_custom_target(aida_c03_safe_headless_application_package",
		"add_executable(aida_c03_safe_headless_manifest_suite",
		"safe-headless application package boundary");
	for (const auto token : std::array<std::string_view, 6>{
		"DEPENDS aida_c03_safe_headless_manifest",
		"AIDA_C03_CUSTOMER_PAYLOAD_FORBIDDEN TRUE",
		"add_dependencies(${application_target} aida_c03_safe_headless_application_package)",
		"target_include_directories(${application_target} PRIVATE \"${AIDA_C03_SAFE_HEADLESS_GENERATED_ROOT}\")",
		"target_compile_options(${application_target} PRIVATE",
		"/FI${AIDA_C03_SAFE_HEADLESS_DIGEST_HEADER}"})
		require_exact_count(application_package, token, 1,
			"application manifest identity and developer-payload exclusion");
	for (const auto token : std::array<std::string_view, 6>{
		"copy_directory", "copy_if_different", "make_directory",
		"${AIDA_C03_SAFE_HEADLESS_STAGE_ROOT}", "rm -rf", "$<TARGET_FILE_DIR:${application_target}>/c03-safe-headless"})
		require_absent(application_package, token,
			"customer application developer-payload copy path");
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
		const auto driver_boundary = read_bounded(root,
			"src/standalone/tests/c03/testlab_runtime/safe_headless_driver_bridge.cpp",
			512ULL * 1024ULL);
		const auto self_guard = read_bounded(root,
			"src/standalone/src/core/anti-tamper/self_guard.hpp",
			4ULL * 1024ULL * 1024ULL);
		const auto materializer = read_bounded(root,
			"src/standalone/tests/c03/testlab_runtime/materialize_safe_headless_manifest.py",
			2ULL * 1024ULL * 1024ULL);
		const auto cmake_manifest = read_bounded(root,
			"cmake/aida_c03_safe_headless_manifest.cmake",
			8ULL * 1024ULL * 1024ULL);
		const auto root_cmake = read_bounded(root,
			"CMakeLists.txt", 16ULL * 1024ULL * 1024ULL);
		const auto package_integration = read_bounded(root,
			"cmake/aida_c03_package_integration.cmake",
			4ULL * 1024ULL * 1024ULL);
		const auto dependency_cmake = read_bounded(root,
			"cmake/aida_c03_dependencies.cmake",
			4ULL * 1024ULL * 1024ULL);
		const auto package_verifier = read_bounded(root,
			"src/standalone/tools/c03_package_verifier/main.cpp",
			2ULL * 1024ULL * 1024ULL);
		const auto path_policy = read_bounded(root,
			"cmake/c03_safe_headless/package_policy_fixture/aida_c03_path_policy.cmake",
			512ULL * 1024ULL);
		const auto path_identity = read_bounded(root,
			"cmake/c03_safe_headless/package_policy_fixture/aida_c03_path_identity.ps1",
			512ULL * 1024ULL);
		const auto distribution_producer = read_bounded(root,
			"packaging/c03_distribution_manifest.ps1",
			4ULL * 1024ULL * 1024ULL);
		const auto distribution_verifier = read_bounded(root,
			"src/standalone/src/core/analysis/build_worker_packaging_integration.cpp",
			8ULL * 1024ULL * 1024ULL);
		const auto distribution_harness = read_bounded(root,
			"src/standalone/tests/c03/build_packaging_integration_harness.cpp",
			4ULL * 1024ULL * 1024ULL);
		const auto package_policy_harness = read_bounded(root,
			"src/standalone/tests/c03/package_distribution_policy/package_distribution_policy_harness.ps1",
			2ULL * 1024ULL * 1024ULL);
		const auto package_policy_stage_spec = read_bounded(root,
			"src/standalone/tests/c03/package_distribution_policy/policy_stage_spec.json",
			256ULL * 1024ULL);
		const auto path_byte_policy = read_bounded(root,
			"packaging/c03_distribution_fixture/path_byte_policy.json",
			256ULL * 1024ULL);
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
		verify_safe_headless_driver_boundary(driver_boundary);
		verify_self_guard_odr_contract(self_guard);
		verify_manifest_registration(cmake_manifest, path_policy, path_identity,
			package_integration);
		verify_distribution_source_leak_policy(distribution_producer,
			distribution_verifier, distribution_harness, package_policy_harness,
			cmake_manifest, package_integration, root_cmake, package_verifier,
			dependency_cmake, path_byte_policy);
		for (const auto token : std::array<std::string_view, 5>{
				"aida.c03.package-policy-stage-fixture.v1", "AiDAStandalone.exe",
				"allowlisted_files_v1", "resources/runtime.bin", "inventory_sources"})
			require_contains(package_policy_stage_spec, token,
				"copy-only package stage fixture specification");
		verify_safe_headless_runtime(safe_headless, materializer,
			cmake_manifest, resource_cases);
		verify_quality_pipeline(quality_pipeline, cmake_manifest);
		verify_surface_authority(root, surface_generator, authority_verifier,
			authority_ledger, surface_baseline, surface_final);
		require_clean_source(main_source, "standalone main source");
		require_clean_source(contracts, "generated MCP contract source");
		require_clean_source(browser, "browser policy source");
		require_clean_source(safe_headless, "safe-headless runtime source");
		require_clean_source(driver_boundary, "safe-headless driver boundary source");
		require_clean_source(cmake_manifest, "safe-headless CMake source");
		require_clean_source(package_integration, "package integration CMake source");
		require_clean_source(dependency_cmake, "dependency CMake source");
		require_clean_source(package_verifier, "production package verifier source");
		require_clean_source(path_policy, "path policy CMake source");
		require_clean_source(path_identity, "path identity PowerShell source");
		require_clean_source(distribution_producer, "distribution producer source");
		require_clean_source(distribution_verifier, "distribution verifier source");
		require_clean_source(distribution_harness, "distribution harness source");
		require_clean_source(package_policy_harness, "package policy harness source");
		require_clean_source(path_byte_policy, "path byte policy source");
		require_clean_source(quality_pipeline, "quality pipeline source");
		require_clean_source(authority_verifier, "authority reproduction verifier");
		return 0;
	} catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
		std::cerr << error.what() << '\n';
		return 1;
	}
}
