#include "source_debug_service.hpp"

#include "debugger_engine.hpp"
#include "debugger_interaction_context.hpp"
#include "../editor/programming_document_service.hpp"
#include "../ui/application_view_registry.hpp"
#include "../ui/task_center.hpp"
#include "../disasm/disasm_view.hpp"
#include "../../helpers/globals.h"

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "debugger_definition_store.hpp"
#include "../analysis/symbol_store.hpp"
#include "../infra/executor.hpp"
#include "../session/analysis_session.hpp"
#include "../../helpers/diag_log.hpp"
#endif

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <limits>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string_view>
#include <unordered_set>

namespace source_debug_service {
namespace {

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
constexpr std::size_t k_max_definitions = 4096;
constexpr std::size_t k_max_locations_per_definition = 64;
constexpr std::size_t k_max_source_file_bytes = 8ULL * 1024ULL * 1024ULL;
constexpr std::size_t k_max_excerpt_line_bytes = 16ULL * 1024ULL;
#endif

struct runtime_t {
	std::mutex operation_mutex;
	std::vector<definition_t> definitions;
	std::string target_key;
	std::string workspace_binary_id;
	std::atomic<bool> operation_pending{false};
	std::atomic<std::uint64_t> request_generation{1};
	std::atomic<std::uint64_t> publication_generation{1};
	std::atomic<std::uint64_t> navigation_generation{0};
	std::atomic<std::uint64_t> consumed_navigation_generation{0};
	std::atomic<std::uint64_t> last_context_signature{0};
	std::shared_ptr<const snapshot_t> publication;
	current_location_t pending_navigation;
	std::string operation_label;
	std::string error;
	std::uint32_t target_pid = 0;
	std::uint64_t stop_generation = 0;
	std::uint64_t workspace_generation = 0;
	std::uint64_t symbol_generation = 0;
};

runtime_t& runtime()
{
	static runtime_t value;
	static std::once_flag initialized;
	std::call_once(initialized, [&]() {
		auto initial = std::make_shared<snapshot_t>();
		initial->generation = 1;
		std::atomic_store_explicit(&value.publication,
			std::shared_ptr<const snapshot_t>(std::move(initial)),
			std::memory_order_release);
	});
	return value;
}

std::uint64_t fnv1a(std::string_view text)
{
	std::uint64_t value = 1469598103934665603ULL;
	for (const char byte : text) {
		const auto ch = static_cast<unsigned char>(byte);
		value ^= ch;
		value *= 1099511628211ULL;
	}
	return value;
}

std::string definition_id(const std::string& canonical, std::uint32_t line)
{
	const std::string identity = canonical + "\n" + std::to_string(line);
	char buffer[40]{};
	std::snprintf(buffer, sizeof(buffer), "source:%016llx:%u",
		static_cast<unsigned long long>(fnv1a(identity)), line);
	return buffer;
}

void rebuild_publication_locked(runtime_t& rt, bool operation_pending)
{
	auto next = std::make_shared<snapshot_t>();
	next->generation = rt.publication_generation.fetch_add(1,
		std::memory_order_acq_rel) + 1;
	next->target_key = rt.target_key;
	next->target_pid = rt.target_pid;
	next->stop_generation = rt.stop_generation;
	next->workspace_generation = rt.workspace_generation;
	next->symbol_generation = rt.symbol_generation;
	next->operation_pending = operation_pending;
	next->operation_label = rt.operation_label;
	next->error = rt.error;
	next->definitions = rt.definitions;
	std::unordered_map<std::string, std::vector<line_marker_t>> marker_build;
	for (const auto& definition : next->definitions) {
		line_marker_t marker;
		marker.line = definition.line;
		marker.state = definition.state;
		marker.enabled = definition.enabled;
		marker.detail = definition.detail;
		marker_build[definition.canonical_path].push_back(std::move(marker));
	}
	for (auto& item : marker_build) {
		auto sorted = std::make_shared<std::vector<line_marker_t>>(std::move(item.second));
		std::sort(sorted->begin(), sorted->end(), [](const auto& left, const auto& right) {
			return left.line < right.line;
		});
		next->markers_by_path.emplace(item.first,
			std::shared_ptr<const std::vector<line_marker_t>>(std::move(sorted)));
	}
	const auto previous = std::atomic_load_explicit(&rt.publication,
		std::memory_order_acquire);
	if (previous) next->current = previous->current;
	std::atomic_store_explicit(&rt.publication,
		std::shared_ptr<const snapshot_t>(std::move(next)),
		std::memory_order_release);
}

void rebuild_publication_locked(runtime_t& rt)
{
	rebuild_publication_locked(rt,
		rt.operation_pending.load(std::memory_order_acquire));
}

void publish_current(runtime_t& rt, current_location_t current)
{
	auto previous = std::atomic_load_explicit(&rt.publication,
		std::memory_order_acquire);
	auto next = previous ? std::make_shared<snapshot_t>(*previous)
		: std::make_shared<snapshot_t>();
	next->generation = rt.publication_generation.fetch_add(1,
		std::memory_order_acq_rel) + 1;
	next->current = std::move(current);
	std::atomic_store_explicit(&rt.publication,
		std::shared_ptr<const snapshot_t>(std::move(next)),
		std::memory_order_release);
}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)

struct context_t {
	std::uint32_t pid = 0;
	std::uint64_t stop_generation = 0;
	std::uint64_t workspace_generation = 0;
	std::uint64_t symbol_generation = 0;
	std::uint64_t breakpoint_generation = 0;
	std::uint64_t rip = 0;
	debugger_engine::dbg_status_t status = debugger_engine::dbg_status_t::idle;
	std::string workspace_binary_id;
};

bool capture_context(context_t& context)
{
	context = {};
	context.pid = driver_bridge::attached_pid();
	context.status = debugger_engine::g_state.status.load(std::memory_order_acquire);
	context.stop_generation = debugger_interaction::current_stop_generation();
	context.symbol_generation = symbol_store::g_source_line_generation.load(
		std::memory_order_acquire);
	context.breakpoint_generation = debugger_engine::g_state.breakpoints_generation.load(
		std::memory_order_acquire);
	debugger_engine::register_set_t registers;
	if (!debugger_engine::try_cached_registers(registers)) return false;
	context.rip = registers.rip;
	std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
	if (!analysis_session::try_active_workspace(workspace)) return false;
	if (workspace) {
		context.workspace_generation = workspace->generation();
		context.workspace_binary_id = workspace->identity().binary_id().to_hex();
	}
	return true;
}

bool context_matches(const context_t& expected)
{
	context_t current;
	if (!capture_context(current)) return false;
	return current.pid == expected.pid &&
		current.stop_generation == expected.stop_generation &&
		current.workspace_generation == expected.workspace_generation &&
		current.workspace_binary_id == expected.workspace_binary_id &&
		current.symbol_generation == expected.symbol_generation &&
		current.rip == expected.rip && current.status == expected.status;
}

std::string source_key(const std::string& canonical, std::uint32_t line)
{
	return canonical + "\n" + std::to_string(line);
}

bool module_loaded_exact(const symbol_store::source_module_snapshot_t& symbols,
	const std::vector<driver_bridge::module_info_t>& modules)
{
	for (const auto& module : modules) {
		if (_stricmp(module.name.c_str(), symbols.module_name.c_str()) == 0 &&
			module.base == symbols.base && module.size == symbols.size)
			return true;
	}
	return false;
}

std::vector<bound_location_t> resolve_locations(const definition_t& definition,
	const std::vector<symbol_store::source_module_snapshot_t>& source_modules,
	const std::vector<driver_bridge::module_info_t>& loaded_modules,
	std::string& detail)
{
	std::vector<bound_location_t> output;
	std::set<std::uint64_t> addresses;
	bool source_data_pending = false;
	bool source_data_error = false;
	std::string source_error;
	const std::string key = source_key(definition.canonical_path, definition.line);
	for (const auto& module : source_modules) {
		if (!module_loaded_exact(module, loaded_modules)) continue;
		if (!module.source_lines) {
			source_data_pending = true;
			continue;
		}
		const auto& table = *module.source_lines;
		if (table.state == pdb_parser::source_line_state_t::unsupported ||
			table.state == pdb_parser::source_line_state_t::no_records ||
			table.state == pdb_parser::source_line_state_t::truncated ||
			table.state == pdb_parser::source_line_state_t::error) {
			source_data_error = true;
			source_error = table.detail;
		}
		auto found = table.lines_by_file_line.find(key);
		if (found == table.lines_by_file_line.end()) continue;
		if (found->second.size() > k_max_locations_per_definition) {
			detail = "The exact file:line maps to more than 64 code locations";
			return {};
		}
		for (const auto line_index : found->second) {
			if (line_index >= table.lines.size()) continue;
			const auto& line = table.lines[line_index];
			if (module.size == 0 || line.rva >= module.size ||
				module.base > (std::numeric_limits<std::uint64_t>::max)() - line.rva)
				continue;
			const auto address = module.base + line.rva;
			if (!addresses.insert(address).second) continue;
			output.push_back({module.module_name, line.rva, address,
				static_cast<std::uint32_t>(output.size()), false});
		}
	}
	if (!output.empty()) {
		detail = output.size() == 1 ? "Resolved to one exact PDB source location"
			: "Resolved to " + std::to_string(output.size()) +
				" exact PDB source locations";
	} else if (source_data_pending) {
		detail = "PDB source-line data is not published for the loaded module yet";
	} else if (source_data_error) {
		detail = source_error.empty() ? "PDB source-line data is unavailable" : source_error;
	} else {
		detail = "No loaded module has an exact PDB record for this file and line";
	}
	return output;
}

bool disarm_definition(definition_t& definition, std::string& error)
{
	std::vector<bound_location_t> retained;
	for (const auto& location : definition.locations) {
		if (location.runtime_owned && !debugger_engine::remove_source_breakpoint(
			definition.id, location.ordinal)) {
			retained.push_back(location);
			if (error.empty()) error = debugger_engine::last_error();
		}
	}
	definition.locations = std::move(retained);
	return definition.locations.empty();
}

void release_definitions_for_target_transition(runtime_t& rt,
	const context_t& context)
{
	if (rt.target_pid != context.pid) {
		if (!debugger_engine::discard_source_breakpoints_for_target_change(
			rt.target_pid, context.pid))
			throw std::runtime_error(debugger_engine::last_error());
		for (auto& definition : rt.definitions) definition.locations.clear();
		return;
	}
	const bool has_runtime_breakpoint = std::any_of(rt.definitions.begin(),
		rt.definitions.end(), [](const auto& definition) {
			return std::any_of(definition.locations.begin(), definition.locations.end(),
				[](const auto& location) { return location.runtime_owned; });
		});
	if (has_runtime_breakpoint &&
		context.status != debugger_engine::dbg_status_t::paused)
		throw std::runtime_error(
			"Pause the target before switching persistent source-breakpoint identity");
	for (auto& definition : rt.definitions) {
		std::string disarm_error;
		if (!disarm_definition(definition, disarm_error))
			throw std::runtime_error(disarm_error.empty()
				? "A previous source breakpoint could not be disarmed"
				: disarm_error);
	}
}

bool arm_definition(definition_t& definition,
	std::vector<bound_location_t> resolved,
	const std::shared_ptr<std::atomic<bool>>& cancelled, std::string& error)
{
	const auto existing = debugger_engine::snapshot_breakpoints();
	std::vector<std::pair<std::string, std::uint32_t>> newly_armed;
	for (auto& location : resolved) {
		if (cancelled->load(std::memory_order_acquire)) {
			for (const auto& armed : newly_armed)
				static_cast<void>(debugger_engine::remove_source_breakpoint(
					armed.first, armed.second));
			error = "Source breakpoint arming was cancelled and rolled back";
			return false;
		}
		bool covered = false;
		for (const auto& breakpoint : existing) {
			if (breakpoint.address != location.address ||
				breakpoint.type != debugger_engine::bp_type_t::software)
				continue;
			covered = true;
			location.runtime_owned = breakpoint.source_definition_id == definition.id &&
				breakpoint.source_location_ordinal == location.ordinal;
			break;
		}
		if (covered) continue;
		if (debugger_engine::add_source_breakpoint(location.address, definition.id,
			definition.file_path, definition.line, location.ordinal) < 0) {
			error = debugger_engine::last_error();
			for (const auto& armed : newly_armed)
				static_cast<void>(debugger_engine::remove_source_breakpoint(
					armed.first, armed.second));
			return false;
		}
		location.runtime_owned = true;
		newly_armed.emplace_back(definition.id, location.ordinal);
	}
	definition.locations = std::move(resolved);
	return true;
}

void load_definitions_locked(runtime_t& rt, const std::string& target_key)
{
	std::vector<definition_t> loaded;
	const auto root = debugger_definition_store::settings_payload();
	const auto& targets = root["targets"];
	if (!targets.contains(target_key) || !targets[target_key].is_object()) {
		rt.definitions.clear();
		return;
	}
	const auto& target = targets[target_key];
	if (!target.contains("source_breakpoints") ||
		!target["source_breakpoints"].is_array()) {
		rt.definitions.clear();
		return;
	}
	for (const auto& item : target["source_breakpoints"]) {
		if (loaded.size() >= k_max_definitions || !item.is_object()) break;
		const std::string path = item.value("file", std::string{});
		const auto line = item.value("line", 0u);
		const std::string canonical = canonical_path(path);
		if (path.empty() || path.size() > 32768 || canonical.empty() || line == 0)
			continue;
		definition_t definition;
		definition.id = definition_id(canonical, line);
		definition.file_path = path;
		definition.canonical_path = canonical;
		definition.line = line;
		const auto duplicate = std::find_if(loaded.begin(), loaded.end(),
			[&](const auto& existing) {
				return existing.canonical_path == canonical && existing.line == line;
			});
		if (duplicate != loaded.end()) continue;
		const auto collision = std::find_if(loaded.begin(), loaded.end(),
			[&](const auto& existing) { return existing.id == definition.id; });
		if (collision != loaded.end())
			throw std::runtime_error("Persistent source-breakpoint identity collision");
		definition.enabled = item.value("enabled", true);
		definition.state = binding_state_t::pending;
		definition.detail = "Awaiting exact target and PDB source-line binding";
		loaded.push_back(std::move(definition));
	}
	rt.definitions = std::move(loaded);
}

void persist_definitions_locked(const runtime_t& rt)
{
	if (rt.target_key.empty()) throw std::runtime_error(
		"A source breakpoint requires an active analysis workspace or target identity");
	auto root = debugger_definition_store::settings_payload();
	auto& target = root["targets"][rt.target_key];
	if (!target.is_object()) target = nlohmann::json::object();
	auto source_breakpoints = nlohmann::json::array();
	for (const auto& definition : rt.definitions) {
		if (source_breakpoints.size() >= k_max_definitions) break;
		source_breakpoints.push_back({{"file", definition.file_path},
			{"line", definition.line}, {"enabled", definition.enabled}});
	}
	target["source_breakpoints"] = std::move(source_breakpoints);
	debugger_definition_store::schedule_settings_save(root.dump());
}

current_location_t resolve_current_location(const context_t& context,
	const std::vector<symbol_store::source_module_snapshot_t>& modules,
	const std::vector<definition_t>& definitions)
{
	current_location_t current;
	if (context.pid == 0 || context.rip == 0) {
		current.detail = "Pause an attached target at a valid instruction to resolve source";
		return current;
	}
	for (const auto& module : modules) {
		if (module.size == 0 || context.rip < module.base ||
			context.rip - module.base >= module.size || !module.source_lines)
			continue;
		const auto& table = *module.source_lines;
		const bool pdb_truncated =
			table.state == pdb_parser::source_line_state_t::truncated;
		const std::uint64_t rva = context.rip - module.base;
		auto after = table.line_by_rva.upper_bound(rva);
		if (after == table.line_by_rva.begin()) {
			current.detail = "No PDB source line precedes the stopped instruction";
			return current;
		}
		--after;
		if (rva - after->first > 0x10000 || after->second >= table.lines.size()) {
			current.detail = "The nearest PDB source line is outside the 64 KiB resolution bound";
			return current;
		}
		const auto& line = table.lines[after->second];
		if (line.file_index >= table.files.size()) {
			current.detail = "The PDB source-line file index is invalid";
			return current;
		}
		current.valid = true;
		current.file_path = table.files[line.file_index].file_path;
		current.canonical_path = canonical_path(current.file_path);
		current.module_name = module.module_name;
		current.line = line.line;
		current.module_rva = line.rva;
		current.address = context.rip;
		for (const auto& definition : definitions) {
			for (const auto& location : definition.locations) {
				if (definition.enabled && location.address == context.rip) {
					current.source_breakpoint_hit = true;
					break;
				}
			}
		}
		std::string bytes;
		const auto read = aida::editor::programming_documents::read_bounded_file(
			std::filesystem::path(current.file_path), k_max_source_file_bytes, bytes);
		if (!read.succeeded) {
			current.source_state = read.detail.find("exceeds") != std::string::npos
				? source_state_t::truncated : source_state_t::missing;
			current.detail = read.detail;
			return current;
		}
		const auto decoded = aida::editor::programming_documents::decode_file_bytes(bytes);
		if (!decoded.succeeded) {
			current.source_state = source_state_t::error;
			current.detail = decoded.detail;
			return current;
		}
		std::vector<std::string_view> lines;
		std::string_view text(decoded.text);
		size_t begin = 0;
		while (begin <= text.size()) {
			const size_t end = text.find('\n', begin);
			lines.push_back(text.substr(begin, end == std::string_view::npos
				? text.size() - begin : end - begin));
			if (end == std::string_view::npos) break;
			begin = end + 1;
		}
		if (current.line == 0 || current.line > lines.size()) {
			current.source_state = source_state_t::error;
			current.detail = "The PDB line number is outside the current source file";
			return current;
		}
		const std::uint32_t first = current.line > 5 ? current.line - 5 : 1;
		const std::uint32_t last = static_cast<std::uint32_t>((std::min)(
			lines.size(), static_cast<size_t>(current.line + 5)));
		for (std::uint32_t line_number = first; line_number <= last; ++line_number) {
			auto value = lines[line_number - 1];
			if (value.size() > k_max_excerpt_line_bytes)
				value = value.substr(0, k_max_excerpt_line_bytes);
			current.excerpt.push_back({line_number, std::string(value),
				line_number == current.line});
		}
		current.source_state = pdb_truncated
			? source_state_t::truncated : source_state_t::available;
		current.detail = pdb_truncated
			? "Exact stopped source line loaded from a truncated PDB source table"
			: "Exact PDB source line and bounded source excerpt loaded";
		return current;
	}
	current.detail = "No loaded PDB source-line table covers the stopped address";
	return current;
}

void reconcile_locked(runtime_t& rt, const context_t& context,
	const std::shared_ptr<std::atomic<bool>>& cancelled)
{
	if (cancelled->load(std::memory_order_acquire))
		throw std::runtime_error("Source-debug reconciliation was cancelled before it started");
	std::vector<driver_bridge::module_info_t> loaded_modules;
	if (context.pid != 0) loaded_modules = driver_bridge::enumerate_modules();
	if (!context_matches(context))
		throw std::runtime_error("Source-debug target context changed before module binding");
	const std::string target_key = context.workspace_binary_id.empty()
		? debugger_definition_store::active_target_key(loaded_modules)
		: "binary:" + context.workspace_binary_id;
	if (target_key != rt.target_key) {
		release_definitions_for_target_transition(rt, context);
		rt.target_key = target_key;
		try {
			load_definitions_locked(rt, target_key);
		} catch (...) {
			rt.target_key.clear();
			throw;
		}
	}
	std::vector<symbol_store::source_module_snapshot_t> source_modules;
	std::string snapshot_error;
	if (!symbol_store::source_modules_snapshot(source_modules, snapshot_error))
		throw std::runtime_error(snapshot_error);
	rt.target_pid = context.pid;
	rt.stop_generation = context.stop_generation;
	rt.workspace_generation = context.workspace_generation;
	rt.workspace_binary_id = context.workspace_binary_id;
	rt.symbol_generation = context.symbol_generation;
	for (auto& definition : rt.definitions) {
		if (cancelled->load(std::memory_order_acquire))
			throw std::runtime_error("Source-debug reconciliation was cancelled");
		definition.target_pid = context.pid;
		definition.stop_generation = context.stop_generation;
		definition.workspace_generation = context.workspace_generation;
		definition.symbol_generation = context.symbol_generation;
		if (!definition.enabled) {
			std::string disarm_error;
			if (context.status != debugger_engine::dbg_status_t::paused &&
				std::any_of(definition.locations.begin(), definition.locations.end(),
					[](const auto& location) { return location.runtime_owned; })) {
				definition.state = binding_state_t::error;
				definition.detail = "Pause the target before disabling an armed source breakpoint";
			} else if (!disarm_definition(definition, disarm_error)) {
				definition.state = binding_state_t::error;
				definition.detail = disarm_error.empty()
					? "The disabled source breakpoint could not be disarmed" : disarm_error;
			} else {
				definition.state = binding_state_t::unbound;
				definition.detail = "The persistent source breakpoint is disabled";
			}
			continue;
		}
		if (context.pid == 0) {
			definition.locations.clear();
			definition.state = binding_state_t::pending;
			definition.detail = "Attach a matching target to bind this persistent source breakpoint";
			continue;
		}
		std::string detail;
		auto resolved = resolve_locations(definition, source_modules, loaded_modules, detail);
		if (resolved.empty()) {
			std::string disarm_error;
			if (context.status != debugger_engine::dbg_status_t::paused &&
				std::any_of(definition.locations.begin(), definition.locations.end(),
					[](const auto& location) { return location.runtime_owned; })) {
				definition.state = binding_state_t::stale;
				definition.detail = "Pause the target before retiring stale source locations";
			} else if (!disarm_definition(definition, disarm_error)) {
				definition.state = binding_state_t::error;
				definition.detail = disarm_error.empty()
					? "A stale source breakpoint could not be disarmed" : disarm_error;
			} else {
				definition.state = binding_state_t::unbound;
				definition.detail = std::move(detail);
			}
			continue;
		}
		if (context.status != debugger_engine::dbg_status_t::paused) {
			definition.locations = std::move(resolved);
			definition.state = binding_state_t::pending;
			definition.detail = "Pause the target to arm the resolved source locations safely";
			continue;
		}
		if (cancelled->load(std::memory_order_acquire))
			throw std::runtime_error("Source-debug reconciliation was cancelled before mutation");
		std::string arm_error;
		if (!arm_definition(definition, std::move(resolved), cancelled, arm_error)) {
			if (cancelled->load(std::memory_order_acquire))
				throw std::runtime_error(arm_error.empty()
					? "Source-debug reconciliation was cancelled during mutation"
					: arm_error);
			definition.state = binding_state_t::error;
			definition.detail = arm_error.empty() ? "Runtime breakpoint arming failed" : arm_error;
			continue;
		}
		definition.state = binding_state_t::bound;
		definition.detail = detail;
	}
	if (!context_matches(context)) {
		for (auto& definition : rt.definitions) {
			definition.state = binding_state_t::stale;
			definition.detail = "Target, stop, workspace, or symbol generation changed during binding";
		}
		throw std::runtime_error("Source-debug binding result became stale before publication");
	}
	auto current = resolve_current_location(context, source_modules, rt.definitions);
	if (current.source_breakpoint_hit &&
		(current.source_state == source_state_t::available ||
			(current.source_state == source_state_t::truncated &&
				!current.excerpt.empty()))) {
		rt.pending_navigation = current;
		rt.navigation_generation.fetch_add(1, std::memory_order_acq_rel);
	}
	publish_current(rt, std::move(current));
}

using operation_t = std::function<void(runtime_t&, const context_t&,
	const std::shared_ptr<std::atomic<bool>>&)>;

struct pending_lifecycle_t {
	explicit pending_lifecycle_t(runtime_t& value) noexcept : rt(value) {}

	bool finish(std::string_view failure) noexcept
	{
		bool expected = false;
		if (!finished.compare_exchange_strong(expected, true,
				std::memory_order_acq_rel))
			return true;
		bool pending_cleared = false;
		const auto clear_pending = [&]() noexcept {
			if (pending_cleared) return;
			rt.operation_pending.store(false, std::memory_order_release);
			pending_cleared = true;
		};
		try {
			std::lock_guard<std::mutex> lock(rt.operation_mutex);
			rt.operation_label.clear();
			try { rt.error.assign(failure.data(), failure.size()); }
			catch (...) {
				try { rt.error = "Source-debug terminal diagnostic allocation failed"; }
				catch (...) { rt.error.clear(); }
			}
			if (!failure.empty())
				rt.last_context_signature.store(0, std::memory_order_release);
			rebuild_publication_locked(rt, false);
			clear_pending();
			return true;
		} catch (const std::exception& exception) {
			clear_pending();
			diag::log_tagged_fmt("source_debug",
				"terminal_publication_failed detail='%s'", exception.what());
		} catch (...) {
			clear_pending();
			diag::log_tagged_fmt("source_debug",
				"terminal_publication_failed detail='unknown exception'");
		}
		return false;
	}

	runtime_t& rt;
	std::atomic<bool> finished{false};
};

struct pending_scope_t {
	pending_scope_t(std::shared_ptr<pending_lifecycle_t> value,
		std::string_view fallback_value) noexcept
		: lifecycle(std::move(value)), fallback(fallback_value) {}
	~pending_scope_t() { if (active && lifecycle) lifecycle->finish(fallback); }
	void dismiss() noexcept { active = false; }

	std::shared_ptr<pending_lifecycle_t> lifecycle;
	std::string_view fallback;
	bool active = true;
};

bool submit_operation(const char* label, const char* action_id,
	operation_t operation, std::string* error)
{
	auto& rt = runtime();
	const auto lifecycle = std::make_shared<pending_lifecycle_t>(rt);
	bool expected = false;
	if (!rt.operation_pending.compare_exchange_strong(expected, true,
		std::memory_order_acq_rel)) {
		if (error) *error = "Another source-debug operation is already running";
		return false;
	}
	pending_scope_t setup_scope(lifecycle, "Source-debug operation setup failed");
	std::shared_ptr<std::atomic<bool>> cancelled;
	std::uint64_t submitted_task_id = 0;
	try {
		context_t context;
		if (!capture_context(context)) {
			const std::string detail =
				"The current debugger/workspace context is temporarily busy";
			lifecycle->finish(detail);
			setup_scope.dismiss();
			if (error) *error = detail;
			return false;
		}
		cancelled = std::make_shared<std::atomic<bool>>(false);
		const auto generation = rt.request_generation.fetch_add(1,
			std::memory_order_acq_rel);
		std::string affected_entity;
		{
			std::lock_guard<std::mutex> lock(rt.operation_mutex);
			rt.operation_label = label;
			rt.error.clear();
			rebuild_publication_locked(rt);
			affected_entity = rt.target_key;
		}
		aida::infra::executor::submission_t submission;
		submission.owner_subsystem = "source_debug";
		submission.label = label;
		submission.thread_class = "target_mutation";
		submission.domain = aida::infra::executor::domain_t::feature_worker;
		submission.priority = 3;
		submission.target_pid = context.pid;
		submission.generation = generation;
		submission.cancel_hook = [cancelled]() {
			cancelled->store(true, std::memory_order_release);
		};
		submission.body = [context, cancelled, lifecycle,
			operation = std::move(operation), label = std::string(label)]() mutable {
			pending_scope_t worker_scope(lifecycle,
				"Source-debug worker terminated before publishing a result");
			auto& inner = runtime();
			std::string failure;
			try {
				std::lock_guard<std::mutex> lock(inner.operation_mutex);
				operation(inner, context, cancelled);
				inner.error.clear();
			} catch (const std::exception& exception) {
				try { failure = exception.what(); }
				catch (...) { failure.clear(); }
			} catch (...) {
				try { failure = "Unknown source-debug worker failure"; }
				catch (...) { failure.clear(); }
			}
			const bool published = lifecycle->finish(failure);
			worker_scope.dismiss();
			if (!published && failure.empty())
				failure = "Source-debug terminal publication failed";
			if (!failure.empty()) {
				diag::log_tagged_fmt("source_debug", "operation_failed label='%s' detail='%s'",
					label.c_str(), failure.c_str());
				throw std::runtime_error(failure);
			}
		};
		const auto submitted = aida::infra::executor::submit(std::move(submission));
		if (!submitted.submitted) {
			const std::string detail = submitted.reject_reason.empty()
				? "The source-debug executor rejected the operation"
				: submitted.reject_reason;
			lifecycle->finish(detail);
			setup_scope.dismiss();
			if (error) *error = detail;
			return false;
		}
		submitted_task_id = submitted.task_id;
		aida::ui::task_center::task_registration_t registration;
		registration.id = "source.debug." + std::to_string(submitted.task_id);
		registration.source = "Source Debugger";
		registration.owner = "source_debug";
		registration.owner_view = "view.debug.source";
		registration.owner_action = action_id;
		registration.target = context.pid == 0 ? context.workspace_binary_id
			: "PID " + std::to_string(context.pid);
		registration.label = label;
		registration.stage = "Queued";
		registration.affected_entity = std::move(affected_entity);
		registration.cancellation_is_safe = true;
		registration.callbacks.cancel = [cancelled, task_id = submitted.task_id]() {
			cancelled->store(true, std::memory_order_release);
			return aida::infra::executor::cancel(task_id);
		};
		if (!aida::ui::task_center::try_register_executor_job(submitted.task_id,
			std::move(registration))) {
			cancelled->store(true, std::memory_order_release);
			static_cast<void>(aida::infra::executor::cancel(submitted.task_id));
			const std::string detail = "Task Center rejected source-debug ownership";
			lifecycle->finish(detail);
			setup_scope.dismiss();
			if (error) *error = detail;
			return false;
		}
		setup_scope.dismiss();
		return true;
	} catch (const std::exception& exception) {
		if (cancelled) cancelled->store(true, std::memory_order_release);
		if (submitted_task_id != 0) {
			try { static_cast<void>(aida::infra::executor::cancel(submitted_task_id)); }
			catch (...) {}
		}
		std::string detail;
		try { detail = exception.what(); }
		catch (...) {
			try { detail = "Source-debug operation setup failed"; } catch (...) {}
		}
		lifecycle->finish(detail);
		setup_scope.dismiss();
		if (error) {
			try { *error = detail; } catch (...) {}
		}
		return false;
	} catch (...) {
		if (cancelled) cancelled->store(true, std::memory_order_release);
		if (submitted_task_id != 0) {
			try { static_cast<void>(aida::infra::executor::cancel(submitted_task_id)); }
			catch (...) {}
		}
		constexpr std::string_view detail = "Source-debug operation setup failed";
		lifecycle->finish(detail);
		setup_scope.dismiss();
		if (error) {
			try { *error = detail; } catch (...) {}
		}
		return false;
	}
}

#endif

}

std::string canonical_path(const std::string& path)
{
	if (path.empty() || path.size() > 32768 || path.find('\0') != std::string::npos)
		return {};
	std::string result = std::filesystem::path(path).lexically_normal().generic_string();
	std::transform(result.begin(), result.end(), result.begin(), [](unsigned char ch) {
		return static_cast<char>(std::tolower(ch));
	});
	return result;
}

const char* binding_state_label(binding_state_t state)
{
	switch (state) {
	case binding_state_t::pending: return "Pending";
	case binding_state_t::bound: return "Bound";
	case binding_state_t::unbound: return "Unbound";
	case binding_state_t::stale: return "Stale";
	case binding_state_t::error: return "Error";
	}
	return "Error";
}

const char* source_state_label(source_state_t state)
{
	switch (state) {
	case source_state_t::unavailable: return "Unavailable";
	case source_state_t::loading: return "Loading";
	case source_state_t::available: return "Available";
	case source_state_t::missing: return "Missing";
	case source_state_t::truncated: return "Truncated";
	case source_state_t::error: return "Error";
	}
	return "Error";
}

snapshot_ptr snapshot()
{
	return std::atomic_load_explicit(&runtime().publication,
		std::memory_order_acquire);
}

marker_snapshot_t markers_for_path(const std::string& path)
{
	marker_snapshot_t output;
	const auto current = snapshot();
	if (!current) return output;
	output.generation = current->generation;
	auto found = current->markers_by_path.find(canonical_path(path));
	if (found != current->markers_by_path.end()) output.markers = found->second;
	return output;
}

void begin_frame()
{
	auto& rt = runtime();
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static bool initialized = false;
	if (!initialized) {
		initialized = true;
		static_cast<void>(debugger_engine::cached_registers());
		std::lock_guard<std::mutex> lock(rt.operation_mutex);
		definition_t definition;
		definition.id = definition_id("c:/aida/preview/sample.cpp", 28);
		definition.file_path = "C:/AiDA/Preview/sample.cpp";
		definition.canonical_path = "c:/aida/preview/sample.cpp";
		definition.line = 28;
		definition.state = binding_state_t::bound;
		definition.detail = "Deterministic Studio preview source breakpoint";
		definition.locations = {{"AiDA_Target", 0x12C0, 0x1400012C0, 0, true}};
		rt.definitions = {std::move(definition)};
		rt.target_key = "preview-debugger-fixture";
		rt.target_pid = debugger_engine::g_state.target_pid;
		rt.stop_generation = debugger_interaction::current_stop_generation();
		current_location_t current;
		current.valid = true;
		current.file_path = "C:/AiDA/Preview/sample.cpp";
		current.canonical_path = "c:/aida/preview/sample.cpp";
		current.module_name = "AiDA_Target";
		current.line = 28;
		current.module_rva = 0x12C0;
		current.address = 0x1400012C0;
		current.source_state = source_state_t::available;
		current.detail = "Deterministic Studio preview source and assembly fixture";
		current.excerpt = {{26, "bool AnalyzeImage(const Image& image) {", false},
			{27, "    if (!image.valid()) return false;", false},
			{28, "    return analyzer.run(image);", true},
			{29, "}", false}};
		rebuild_publication_locked(rt);
		publish_current(rt, std::move(current));
	} else {
		const std::uint32_t target_pid = debugger_engine::g_state.target_pid;
		const std::uint64_t stop_generation =
			debugger_interaction::current_stop_generation();
		std::lock_guard<std::mutex> lock(rt.operation_mutex);
		if (rt.target_pid != target_pid || rt.stop_generation != stop_generation) {
			rt.target_pid = target_pid;
			rt.stop_generation = stop_generation;
			rebuild_publication_locked(rt);
		}
	}
#else
	context_t context;
	if (capture_context(context)) {
		debugger_interaction::synchronize_target_snapshot(context.pid,
			context.status != debugger_engine::dbg_status_t::running,
			context.rip, 0);
		context.stop_generation = debugger_interaction::current_stop_generation();
		const std::string identity = std::to_string(context.pid) + ":" +
			std::to_string(context.stop_generation) + ":" +
			std::to_string(context.workspace_generation) + ":" +
			std::to_string(context.symbol_generation) + ":" +
			std::to_string(context.breakpoint_generation) + ":" +
			std::to_string(context.rip) + ":" + context.workspace_binary_id;
		const auto signature = fnv1a(identity);
		const auto previous = rt.last_context_signature.load(std::memory_order_acquire);
		if (previous != signature &&
			!rt.operation_pending.load(std::memory_order_acquire)) {
			std::string submit_error;
			if (submit_operation("Reconcile source breakpoints",
				"debug.source.rebind", [](runtime_t& inner, const context_t& captured,
					const std::shared_ptr<std::atomic<bool>>& cancelled) {
					reconcile_locked(inner, captured, cancelled);
				}, &submit_error))
				rt.last_context_signature.store(signature, std::memory_order_release);
		}
	}
#endif
	const auto navigation = rt.navigation_generation.load(std::memory_order_acquire);
	if (navigation != 0 && navigation != rt.consumed_navigation_generation.load(
		std::memory_order_acquire)) {
		current_location_t location;
		std::unique_lock<std::mutex> lock(rt.operation_mutex, std::try_to_lock);
		if (!lock.owns_lock()) return;
		location = rt.pending_navigation;
		lock.unlock();
		if (location.valid &&
			(location.source_state == source_state_t::available ||
				(location.source_state == source_state_t::truncated &&
					!location.excerpt.empty()))) {
			static_cast<void>(file_tabs::request_document_open(location.file_path,
				std::filesystem::path(location.file_path).filename().string(),
				static_cast<int>(location.line - 1), 0));
			const auto disassembly = disasm_view::capture_selected_workspace();
			if (disassembly) {
				disasm_view::goto_address(location.address, disassembly);
				static_cast<void>(aida::ui::application_views::open_or_focus(
					aida::ui::stable_view_id_t("document.disassembly")));
			}
			static_cast<void>(aida::ui::application_views::open_or_focus(
				aida::ui::stable_view_id_t("view.debug.source")));
		}
		rt.consumed_navigation_generation.store(navigation,
			std::memory_order_release);
	}
}

bool request_toggle(const std::string& file_path, std::uint32_t line,
	std::string* error)
{
	const std::string canonical = canonical_path(file_path);
	if (canonical.empty() || line == 0) {
		if (error) *error = "A path-backed source document and valid line are required";
		return false;
	}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	auto& rt = runtime();
	std::lock_guard<std::mutex> lock(rt.operation_mutex);
	const auto id = definition_id(canonical, line);
	auto found = std::find_if(rt.definitions.begin(), rt.definitions.end(),
		[&](const auto& item) {
			return item.canonical_path == canonical && item.line == line;
		});
	if (found == rt.definitions.end()) {
		if (std::any_of(rt.definitions.begin(), rt.definitions.end(),
			[&](const auto& item) { return item.id == id; })) {
			if (error) *error = "Source-breakpoint identity collision";
			return false;
		}
		definition_t definition;
		definition.id = id;
		definition.file_path = file_path;
		definition.canonical_path = canonical;
		definition.line = line;
		definition.state = binding_state_t::pending;
		definition.detail = "Preview source breakpoint awaiting fixture binding";
		rt.definitions.push_back(std::move(definition));
	} else {
		rt.definitions.erase(found);
	}
	rebuild_publication_locked(rt);
	return true;
#else
	return submit_operation("Toggle source breakpoint", "debug.source.toggle_breakpoint",
		[file_path, canonical, line](runtime_t& rt, const context_t& context,
			const std::shared_ptr<std::atomic<bool>>& cancelled) {
			std::vector<driver_bridge::module_info_t> modules;
			if (context.pid != 0) modules = driver_bridge::enumerate_modules();
			const std::string target_key = context.workspace_binary_id.empty()
				? debugger_definition_store::active_target_key(modules)
				: "binary:" + context.workspace_binary_id;
			if (target_key.empty()) throw std::runtime_error(
				"Open an analysis workspace or attach a target before defining a source breakpoint");
			if (rt.target_key != target_key) {
				release_definitions_for_target_transition(rt, context);
				rt.target_key = target_key;
				try {
					load_definitions_locked(rt, target_key);
				} catch (...) {
					rt.target_key.clear();
					throw;
				}
			}
			const auto id = definition_id(canonical, line);
			auto found = std::find_if(rt.definitions.begin(), rt.definitions.end(),
				[&](const auto& item) {
					return item.canonical_path == canonical && item.line == line;
				});
			if (found != rt.definitions.end()) {
				if (!found->locations.empty() && context.pid != 0 &&
					context.status != debugger_engine::dbg_status_t::paused)
					throw std::runtime_error("Pause the target before removing an armed source breakpoint");
				std::string disarm_error;
				if (!disarm_definition(*found, disarm_error))
					throw std::runtime_error(disarm_error.empty()
						? "The source breakpoint could not be disarmed" : disarm_error);
				rt.definitions.erase(found);
			} else {
				if (rt.definitions.size() >= k_max_definitions)
					throw std::runtime_error("Source breakpoint definitions reached the 4,096-item bound");
				if (std::any_of(rt.definitions.begin(), rt.definitions.end(),
					[&](const auto& item) { return item.id == id; }))
					throw std::runtime_error("Source-breakpoint identity collision");
				definition_t definition;
				definition.id = id;
				definition.file_path = file_path;
				definition.canonical_path = canonical;
				definition.line = line;
				definition.state = binding_state_t::pending;
				definition.detail = "Awaiting exact PDB source-line binding";
				rt.definitions.push_back(std::move(definition));
			}
			persist_definitions_locked(rt);
			reconcile_locked(rt, context, cancelled);
		}, error);
#endif
}

bool request_remove(const std::string& id, std::string* error)
{
	if (id.empty()) {
		if (error) *error = "Select a source breakpoint definition first";
		return false;
	}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	auto& rt = runtime();
	std::lock_guard<std::mutex> lock(rt.operation_mutex);
	rt.definitions.erase(std::remove_if(rt.definitions.begin(), rt.definitions.end(),
		[&](const auto& item) { return item.id == id; }), rt.definitions.end());
	rebuild_publication_locked(rt);
	return true;
#else
	return submit_operation("Remove source breakpoint", "debug.source.remove_breakpoint",
		[id](runtime_t& rt, const context_t& context,
			const std::shared_ptr<std::atomic<bool>>& cancelled) {
			auto found = std::find_if(rt.definitions.begin(), rt.definitions.end(),
				[&](const auto& item) { return item.id == id; });
			if (found == rt.definitions.end())
				throw std::runtime_error("The source breakpoint definition no longer exists");
			if (!found->locations.empty() && context.pid != 0 &&
				context.status != debugger_engine::dbg_status_t::paused)
				throw std::runtime_error("Pause the target before removing an armed source breakpoint");
			std::string disarm_error;
			if (!disarm_definition(*found, disarm_error))
				throw std::runtime_error(disarm_error.empty()
					? "The source breakpoint could not be disarmed" : disarm_error);
			rt.definitions.erase(found);
			persist_definitions_locked(rt);
			reconcile_locked(rt, context, cancelled);
		}, error);
#endif
}

bool request_rebind(std::string* error)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static_cast<void>(error);
	return true;
#else
	return submit_operation("Rebind source breakpoints", "debug.source.rebind",
		[](runtime_t& rt, const context_t& context,
			const std::shared_ptr<std::atomic<bool>>& cancelled) {
			reconcile_locked(rt, context, cancelled);
		}, error);
#endif
}

bool request_open_source(const std::string& file_path, std::uint32_t line,
	std::string* error)
{
	if (canonical_path(file_path).empty() || line == 0) {
		if (error) *error = "A path-backed source document and valid line are required";
		return false;
	}
	if (!file_tabs::request_document_open(file_path,
		std::filesystem::path(file_path).filename().string(),
		static_cast<int>(line - 1), 0)) {
		if (error) *error = "The source document open request was rejected";
		return false;
	}
	static_cast<void>(aida::ui::application_views::open_or_focus(
		aida::ui::stable_view_id_t("document.code")));
	return true;
}

bool request_open_current_source(std::string* error)
{
	const auto current = snapshot();
	if (!current || !current->current.valid ||
		(current->current.source_state != source_state_t::available &&
			(current->current.source_state != source_state_t::truncated ||
				current->current.excerpt.empty()))) {
		if (error) *error = current ? current->current.detail
			: "No source location is published";
		return false;
	}
	return request_open_source(current->current.file_path,
		current->current.line, error);
}

bool request_open_current_disassembly(std::string* error)
{
	const auto current = snapshot();
	if (!current || !current->current.valid || current->current.address == 0) {
		if (error) *error = "No resolved stopped address is available";
		return false;
	}
	const auto context = disasm_view::capture_selected_workspace();
	if (!context) {
		if (error) *error = "Open the matching analysis workspace first";
		return false;
	}
	disasm_view::goto_address(current->current.address, context);
	static_cast<void>(aida::ui::application_views::open_or_focus(
		aida::ui::stable_view_id_t("document.disassembly")));
	return true;
}

}
