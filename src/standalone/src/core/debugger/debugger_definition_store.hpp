#pragma once

#include "debugger_engine.hpp"
#include "standalone_driver.hpp"
#include "../settings/standalone_settings.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../infra/executor.hpp"
#else
#include "../../preview/ui_task_executor.hpp"
#endif
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../session/analysis_session.hpp"
#include "../helpers/diag_log.hpp"
#endif

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <string>
#include <vector>

namespace debugger_definition_store {

inline constexpr std::size_t k_max_definitions = 4096;
inline constexpr std::size_t k_max_text = 1024;

struct module_binding_t {
	std::string name;
	std::uint64_t offset = 0;
	std::uint32_t size = 0;
	bool valid = false;
};

struct runtime_state_t {
	std::string target_key;
	std::uint32_t target_pid = 0;
	std::uint64_t breakpoint_generation = 0;
	std::uint64_t watch_generation = 0;
	int synchronized_frame = -1;
};

inline runtime_state_t& runtime_state() {
	static runtime_state_t value;
	return value;
}

inline std::string lowercase(std::string value) {
	std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
		return static_cast<char>(std::tolower(c));
	});
	return value;
}

inline std::string bounded(std::string value) {
	if (value.size() > k_max_text)
		value.resize(k_max_text);
	return value;
}

inline std::string active_target_key(const std::vector<driver_bridge::module_info_t>& modules) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	return "preview-debugger-fixture";
#else
	auto workspace = analysis_session::active_workspace();
	if (workspace)
		return "binary:" + workspace->identity().binary_id().to_hex();
	const driver_bridge::module_info_t* main_module = nullptr;
	for (const auto& module : modules) {
		if (module.size == 0 || (main_module && module.base >= main_module->base))
			continue;
		main_module = &module;
	}
	if (!main_module)
		return {};
	return "process:" + lowercase(bounded(main_module->name)) + ":" +
		std::to_string(main_module->size);
#endif
}

inline module_binding_t bind_address(
	std::uint64_t address, const std::vector<driver_bridge::module_info_t>& modules) {
	for (const auto& module : modules) {
		const std::uint64_t end = module.base + static_cast<std::uint64_t>(module.size);
		if (module.size != 0 && end >= module.base && address >= module.base && address < end)
			return {bounded(module.name), address - module.base, module.size, true};
	}
	return {};
}

inline bool resolve_binding(const std::string& name, std::uint32_t size,
	std::uint64_t offset, const std::vector<driver_bridge::module_info_t>& modules,
	std::uint64_t& address, std::string& status) {
	const std::string canonical = lowercase(name);
	const driver_bridge::module_info_t* match = nullptr;
	for (const auto& module : modules) {
		if (lowercase(module.name) != canonical || module.size != size)
			continue;
		if (match != nullptr) {
			status = "Multiple loaded modules match the persisted identity";
			return false;
		}
		match = &module;
	}
	if (!match) {
		status = "The persisted module is not loaded or its image size changed";
		return false;
	}
	if (offset >= match->size || match->base > (std::numeric_limits<std::uint64_t>::max)() - offset) {
		status = "The persisted module offset is outside the current image";
		return false;
	}
	address = match->base + offset;
	status = "Resolved from module-relative identity";
	return true;
}

inline std::string decimal(std::uint64_t value) {
	return std::to_string(value);
}

inline bool parse_decimal(const nlohmann::json& value, std::uint64_t& output) {
	if (!value.is_string())
		return false;
	const std::string text = value.get<std::string>();
	if (text.empty())
		return false;
	char* end = nullptr;
	errno = 0;
	const auto parsed = std::strtoull(text.c_str(), &end, 10);
	if (errno != 0 || !end || *end != '\0')
		return false;
	output = static_cast<std::uint64_t>(parsed);
	return true;
}

inline bool parse_numeric_watch(const std::string& expression, std::uint64_t& address,
	bool& dereference) {
	std::string text = expression;
	text.erase(text.begin(), std::find_if(text.begin(), text.end(), [](unsigned char c) {
		return !std::isspace(c);
	}));
	text.erase(std::find_if(text.rbegin(), text.rend(), [](unsigned char c) {
		return !std::isspace(c);
	}).base(), text.end());
	dereference = text.size() >= 2 && text.front() == '[' && text.back() == ']';
	if (dereference)
		text = text.substr(1, text.size() - 2);
	char* end = nullptr;
	errno = 0;
	const auto parsed = std::strtoull(text.c_str(), &end, 0);
	if (errno != 0 || !end || *end != '\0' || parsed == 0)
		return false;
	address = static_cast<std::uint64_t>(parsed);
	return true;
}

inline std::string resolved_watch_expression(std::uint64_t address, bool dereference) {
	char buffer[48];
	std::snprintf(buffer, sizeof(buffer), dereference ? "[0x%016llX]" : "0x%016llX",
		static_cast<unsigned long long>(address));
	return buffer;
}

inline nlohmann::json settings_payload() {
	std::lock_guard<std::recursive_mutex> lock(sa_settings_detail::io_mutex());
	if (g_sa_settings.debugger_definitions_json.empty())
		return nlohmann::json{{"schema", 1}, {"targets", nlohmann::json::object()}};
	auto parsed = nlohmann::json::parse(g_sa_settings.debugger_definitions_json, nullptr, false);
	if (!parsed.is_object() || parsed.value("schema", 0) != 1 ||
		!parsed.contains("targets") || !parsed["targets"].is_object())
		return nlohmann::json{{"schema", 1}, {"targets", nlohmann::json::object()}};
	return parsed;
}

inline void schedule_settings_save(std::string payload) {
	{
		std::lock_guard<std::recursive_mutex> lock(sa_settings_detail::io_mutex());
		if (g_sa_settings.debugger_definitions_json == payload)
			return;
		g_sa_settings.debugger_definitions_json = std::move(payload);
	}
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "debugger";
	submission.label = "debugger.persist_definitions";
	submission.thread_class = "settings_persistence";
	submission.domain = aida::infra::executor::domain_t::feature_worker;
	submission.priority = 5;
	submission.body = []() {
		if (!g_sa_settings.save())
			diag::log_tagged_fmt("debugger_persistence", "definition_save_failed detail='%s'",
				g_sa_settings.last_error().c_str());
	};
	if (!aida::infra::executor::submit(std::move(submission)).submitted)
		diag::log_tagged("debugger_persistence", "definition_save_queue_rejected");
#endif
}

inline void load_target(const std::string& target_key,
	const std::vector<driver_bridge::module_info_t>& modules) {
	const auto root = settings_payload();
	const auto& targets = root["targets"];
	if (!targets.contains(target_key) || !targets[target_key].is_object()) {
		debugger_engine::restore_breakpoints_and_watches({}, {});
		return;
	}
	const auto& target = targets[target_key];
	std::vector<debugger_engine::breakpoint_t> breakpoints;
	std::vector<debugger_engine::watch_entry_t> watches;

	if (target.contains("breakpoints") && target["breakpoints"].is_array()) {
		for (const auto& item : target["breakpoints"]) {
			if (breakpoints.size() >= k_max_definitions || !item.is_object())
				break;
			const std::string module = bounded(item.value("module", std::string{}));
			const auto module_size = item.value("module_size", 0u);
			std::uint64_t offset = 0;
			if (module.empty() || module_size == 0 || !item.contains("offset") ||
				!parse_decimal(item["offset"], offset))
				continue;
			const int type = item.value("type", 0);
			if (type < 0 || type >= static_cast<int>(debugger_engine::bp_type_t::COUNT))
				continue;
			debugger_engine::breakpoint_t breakpoint;
			breakpoint.type = static_cast<debugger_engine::bp_type_t>(type);
			breakpoint.state = debugger_engine::bp_state_t::disabled;
			breakpoint.size = (std::max)(1, (std::min)(8, item.value("size", 1)));
			breakpoint.name = bounded(item.value("name", std::string{}));
			breakpoint.condition = bounded(item.value("condition", std::string{}));
			breakpoint.log_text = bounded(item.value("log_text", std::string{}));
			breakpoint.auto_continue = item.value("auto_continue", false);
			breakpoint.definition_module = module;
			breakpoint.definition_module_offset = offset;
			breakpoint.definition_module_size = module_size;
			breakpoint.persistent_definition = true;
			breakpoint.definition_resolved = resolve_binding(module, module_size, offset,
				modules, breakpoint.address, breakpoint.definition_status);
			if (!breakpoint.definition_resolved)
				breakpoint.address = 0;
			breakpoints.push_back(std::move(breakpoint));
		}
	}

	if (target.contains("watches") && target["watches"].is_array()) {
		for (const auto& item : target["watches"]) {
			if (watches.size() >= k_max_definitions || !item.is_object())
				break;
			std::string expression = bounded(item.value("expression", std::string{}));
			if (expression.empty())
				continue;
			debugger_engine::watch_entry_t watch;
			watch.persistent_expression = expression;
			watch.persistent_definition = true;
			watch.definition_module = bounded(item.value("module", std::string{}));
			watch.definition_module_size = item.value("module_size", 0u);
			std::uint64_t offset = 0;
			const bool has_binding = !watch.definition_module.empty() &&
				watch.definition_module_size != 0 && item.contains("offset") &&
				parse_decimal(item["offset"], offset);
			watch.definition_module_offset = offset;
			if (has_binding) {
				std::uint64_t address = 0;
				std::string status;
				watch.definition_resolved = resolve_binding(watch.definition_module,
					watch.definition_module_size, offset, modules, address, status);
				if (watch.definition_resolved)
					watch.expression = resolved_watch_expression(address, item.value("dereference", false));
				else {
					watch.expression = expression;
					watch.error = status;
				}
			} else {
				watch.expression = expression;
				watch.definition_resolved = true;
			}
			watches.push_back(std::move(watch));
		}
	}

	debugger_engine::restore_breakpoints_and_watches(std::move(breakpoints), std::move(watches));
}

inline void save_target(const std::string& target_key,
	const std::vector<driver_bridge::module_info_t>& modules) {
	nlohmann::json root = settings_payload();
	nlohmann::json breakpoints = nlohmann::json::array();
	for (const auto& breakpoint : debugger_engine::snapshot_breakpoints()) {
		if (breakpoints.size() >= k_max_definitions)
			break;
		if (breakpoint.is_internal)
			continue;
		module_binding_t binding;
		if (breakpoint.persistent_definition && !breakpoint.definition_module.empty())
			binding = {breakpoint.definition_module, breakpoint.definition_module_offset,
				breakpoint.definition_module_size, true};
		else
			binding = bind_address(breakpoint.address, modules);
		if (!binding.valid)
			continue;
		breakpoints.push_back({
			{"module", binding.name}, {"module_size", binding.size},
			{"offset", decimal(binding.offset)}, {"type", static_cast<int>(breakpoint.type)},
			{"size", breakpoint.size}, {"name", bounded(breakpoint.name)},
			{"condition", bounded(breakpoint.condition)}, {"log_text", bounded(breakpoint.log_text)},
			{"auto_continue", breakpoint.auto_continue}
		});
	}

	nlohmann::json watches = nlohmann::json::array();
	for (const auto& watch : debugger_engine::snapshot_watches()) {
		if (watches.size() >= k_max_definitions)
			break;
		const std::string expression = bounded(watch.persistent_expression.empty()
			? watch.expression : watch.persistent_expression);
		if (expression.empty())
			continue;
		nlohmann::json item{{"expression", expression}};
		module_binding_t binding;
		bool dereference = false;
		if (watch.persistent_definition && !watch.definition_module.empty()) {
			binding = {watch.definition_module, watch.definition_module_offset,
				watch.definition_module_size, true};
			dereference = !expression.empty() && expression.front() == '[';
		} else {
			std::uint64_t address = 0;
			if (parse_numeric_watch(expression, address, dereference))
				binding = bind_address(address, modules);
		}
		if (binding.valid) {
			item["module"] = binding.name;
			item["module_size"] = binding.size;
			item["offset"] = decimal(binding.offset);
			item["dereference"] = dereference;
		}
		watches.push_back(std::move(item));
	}

	root["targets"][target_key] = {
		{"breakpoints", std::move(breakpoints)},
		{"watches", std::move(watches)}
	};
	schedule_settings_save(root.dump());
}

inline void synchronize(int frame_count) {
	auto& state = runtime_state();
	if (state.synchronized_frame == frame_count)
		return;
	state.synchronized_frame = frame_count;
	const std::uint32_t pid = driver_bridge::attached_pid();
	const auto modules = pid == 0 ? std::vector<driver_bridge::module_info_t>{} :
		driver_bridge::enumerate_modules();
	const std::string target_key = pid == 0 ? std::string{} : active_target_key(modules);
	if (pid == 0 || target_key.empty()) {
		if (pid == 0 && !state.target_key.empty()) {
			const auto breakpoint_generation = debugger_engine::g_state.breakpoints_generation.load(
				std::memory_order_acquire);
			const auto watch_generation = debugger_engine::g_state.watches_generation.load(
				std::memory_order_acquire);
			if (state.breakpoint_generation != breakpoint_generation ||
				state.watch_generation != watch_generation) {
				save_target(state.target_key, {});
				state.breakpoint_generation = breakpoint_generation;
				state.watch_generation = watch_generation;
			}
		}
		state.target_pid = 0;
		return;
	}
	if (state.target_pid != pid || state.target_key != target_key) {
		load_target(target_key, modules);
		state.target_pid = pid;
		state.target_key = target_key;
		state.breakpoint_generation = debugger_engine::g_state.breakpoints_generation.load(
			std::memory_order_acquire);
		state.watch_generation = debugger_engine::g_state.watches_generation.load(
			std::memory_order_acquire);
		return;
	}
	const auto breakpoint_generation = debugger_engine::g_state.breakpoints_generation.load(
		std::memory_order_acquire);
	const auto watch_generation = debugger_engine::g_state.watches_generation.load(
		std::memory_order_acquire);
	if (state.breakpoint_generation == breakpoint_generation &&
		state.watch_generation == watch_generation)
		return;
	save_target(target_key, modules);
	state.breakpoint_generation = breakpoint_generation;
	state.watch_generation = watch_generation;
}

}
