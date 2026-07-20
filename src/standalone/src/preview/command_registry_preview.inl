#include "../core/ai/command_registry.hpp"
#include "../core/ui/application_ui_runtime.hpp"
#include "shell_preview.hpp"

#include <algorithm>
#include <cctype>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace aida::commands {

namespace {

std::mutex& preview_mutex()
{
	static std::mutex value;
	return value;
}

std::string& preview_error()
{
	static std::string value;
	return value;
}

std::string lower_ascii(std::string value)
{
	std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
		return static_cast<char>(std::tolower(c));
	});
	return value;
}

std::string trim_copy(const std::string& value)
{
	std::size_t first = 0;
	std::size_t last = value.size();
	while (first < last && (value[first] == ' ' || value[first] == '\t' ||
		value[first] == '\r' || value[first] == '\n'))
		++first;
	while (last > first && (value[last - 1] == ' ' || value[last - 1] == '\t' ||
		value[last - 1] == '\r' || value[last - 1] == '\n'))
		--last;
	return value.substr(first, last - first);
}

int fuzzy_score(const std::string& query, const std::string& target)
{
	if (query.empty())
		return 0;
	std::size_t query_index = 0;
	std::size_t target_index = 0;
	int last_match = -1;
	int gap_penalty = 0;
	int matched = 0;
	while (query_index < query.size() && target_index < target.size()) {
		if (query[query_index] == target[target_index]) {
			if (last_match >= 0)
				gap_penalty += static_cast<int>(target_index) - last_match - 1;
			last_match = static_cast<int>(target_index);
			++query_index;
			++matched;
		}
		++target_index;
	}
	if (query_index < query.size())
		return -1;
	return 1000 - gap_penalty - static_cast<int>(target.size()) + matched * 8;
}

std::vector<command_t>& preview_commands()
{
	static std::vector<command_t> value = [] {
		std::vector<command_t> commands;

		command_t analyze;
		analyze.name = "analyze-entrypoint";
		analyze.description = "Analyze the active binary entry point and initialization chain";
		analyze.source = command_source_t::builtin;
		analyze.template_text = "Analyze the active binary entry point. Trace initialization, anti-analysis checks, unpacking transitions, and the first stable control-flow handoff. $ARGUMENTS";
		analyze.placeholder_hints = {"focus"};
		commands.push_back(std::move(analyze));

		command_t xrefs;
		xrefs.name = "find-security-xrefs";
		xrefs.description = "Find cross-references that influence a security decision";
		xrefs.source = command_source_t::builtin;
		xrefs.template_text = "Find every code and data cross-reference that can influence $ARGUMENTS. Group direct writers, indirect writers, readers, and serialization boundaries.";
		xrefs.placeholder_hints = {"symbol or address"};
		commands.push_back(std::move(xrefs));

		command_t rename;
		rename.name = "rename-symbol";
		rename.description = "Stage a semantic rename for the selected symbol";
		rename.source = command_source_t::builtin;
		rename.resolver = [](const std::vector<std::string>& args, std::string& out) {
			out = args.empty()
				? "Select a symbol and provide the semantic name to stage a rename."
				: "Preview rename receipt: " + args.front();
			return true;
		};
		commands.push_back(std::move(rename));

		command_t abi;
		abi.name = "windows-abi";
		abi.description = "Search Windows ABI and calling-convention references";
		abi.source = command_source_t::skill;
		abi.template_text = "Use the Windows ABI reference skill to resolve $ARGUMENTS. Include structure layout, calling convention, ownership, and version constraints.";
		abi.placeholder_hints = {"API, type, or convention"};
		abi.source_path = "skills/windows-abi/SKILL.md";
		commands.push_back(std::move(abi));

		command_t memory;
		memory.name = "inspect-memory-region";
		memory.description = "Inspect the selected address with the local memory tools";
		memory.source = command_source_t::mcp;
		memory.template_text = "Inspect memory at $ARGUMENTS. Correlate region protection, module ownership, references, decoded instructions, and nearby strings.";
		memory.placeholder_hints = {"address or range"};
		memory.source_path = "aida-local-tools";
		commands.push_back(std::move(memory));

		command_t triage;
		triage.name = "malware-triage";
		triage.description = "Delegate structured binary triage to the malware analysis agent";
		triage.source = command_source_t::agent;
		triage.agent_override = "malware-triage";
		triage.subtask = true;
		triage.resolver = [](const std::vector<std::string>& args, std::string& out) {
			out = "Malware triage agent selected";
			if (!args.empty())
				out += ": " + args.front();
			return true;
		};
		commands.push_back(std::move(triage));

		return commands;
	}();
	return value;
}

void append_application_actions(std::vector<command_t>& result)
{
	const auto actions = aida::ui::application_ui::list_actions(
		aida::ui::action_surface_t::command_palette);
	result.reserve(result.size() + actions.size());
	for (const auto& action : actions) {
		if (!action.visible)
			continue;
		command_t command;
		command.name = std::string("action:") + action.id;
		command.display_name = action.label;
		command.description = action.description;
		command.category = action.category;
		command.shortcut = action.shortcut;
		command.application_action_id = action.id;
		command.disabled_reason = action.disabled_reason;
		command.source = command_source_t::builtin;
		command.enabled = action.enabled;
		result.push_back(std::move(command));
	}
}

}

bool initialize()
{
	std::lock_guard<std::mutex> lock(preview_mutex());
	preview_error().clear();
	return true;
}

bool reindex()
{
	std::lock_guard<std::mutex> lock(preview_mutex());
	preview_error().clear();
	return true;
}

std::vector<command_t> list()
{
	std::vector<command_t> result;
	{
		std::lock_guard<std::mutex> lock(preview_mutex());
		result = preview_commands();
	}
	append_application_actions(result);
	return result;
}

bool find(const std::string& name, command_t& out)
{
	std::lock_guard<std::mutex> lock(preview_mutex());
	const std::string wanted = lower_ascii(name);
	const auto& commands = preview_commands();
	const auto it = std::find_if(commands.begin(), commands.end(), [&](const command_t& command) {
		return lower_ascii(command.name) == wanted;
	});
	if (it == commands.end()) {
		preview_error() = "Unknown command: " + name;
		return false;
	}
	out = *it;
	preview_error().clear();
	return true;
}

std::vector<command_t> fuzzy_search(const std::string& query, int limit)
{
	std::vector<command_t> available;
	{
		std::lock_guard<std::mutex> lock(preview_mutex());
		available = preview_commands();
	}
	append_application_actions(available);
	const std::string needle = lower_ascii(trim_copy(query));
	if (needle.empty()) {
		std::sort(available.begin(), available.end(), [](const command_t& lhs,
			const command_t& rhs) { return lhs.name < rhs.name; });
		if (limit > 0 && static_cast<int>(available.size()) > limit)
			available.resize(static_cast<std::size_t>(limit));
		return available;
	}

	std::vector<std::pair<int, const command_t*>> ranked;
	ranked.reserve(available.size());
	for (const auto& command : available) {
		const std::string name = lower_ascii(
			command.display_name.empty() ? command.name : command.display_name);
		const std::string description = lower_ascii(command.description);
		const std::string category = lower_ascii(command.category);
		const std::string shortcut = lower_ascii(command.shortcut);
		int score = fuzzy_score(needle, name);
		if (score < 0) {
			const int description_score = fuzzy_score(needle, description);
			const int category_score = fuzzy_score(needle, category);
			const int shortcut_score = fuzzy_score(needle, shortcut);
			if (description_score < 0 && category_score < 0 && shortcut_score < 0)
				continue;
			score = (std::max)(description_score - 200,
				(std::max)(category_score - 120, shortcut_score - 80));
		}
		ranked.emplace_back(score, &command);
	}
	std::stable_sort(ranked.begin(), ranked.end(), [](const auto& lhs, const auto& rhs) {
		if (lhs.first != rhs.first) return lhs.first > rhs.first;
		return lhs.second->name < rhs.second->name;
	});
	std::vector<command_t> result;
	result.reserve(ranked.size());
	for (const auto& entry : ranked)
		result.push_back(*entry.second);
	if (limit > 0 && static_cast<int>(result.size()) > limit)
		result.resize(static_cast<std::size_t>(limit));
	return result;
}

bool execute(const std::string& name, const std::vector<std::string>& args, std::string& out_resolved_text)
{
	command_t command;
	if (!find(name, command))
		return false;
	if (command.resolver) {
		const bool result = command.resolver(args, out_resolved_text);
		if (!result) {
			std::lock_guard<std::mutex> lock(preview_mutex());
			preview_error() = "Command resolver rejected the preview action";
		}
		if (result)
			aida::preview::record(aida::preview::shell_action_t::chat_send, "command:" + name);
		return result;
	}
	out_resolved_text = apply_placeholders(command.template_text, args);
	aida::preview::record(aida::preview::shell_action_t::chat_send, "command:" + name);
	return true;
}

const std::string& last_error()
{
	return preview_error();
}

std::vector<std::string> extract_placeholder_hints(const std::string& template_text)
{
	if (template_text.find("$ARGUMENTS") == std::string::npos)
		return {};
	return {"arguments"};
}

std::string apply_placeholders(const std::string& template_text, const std::vector<std::string>& args)
{
	std::string joined;
	for (std::size_t i = 0; i < args.size(); ++i) {
		if (i != 0) joined.push_back(' ');
		joined += args[i];
	}
	std::string result = template_text;
	std::size_t position = 0;
	while ((position = result.find("$ARGUMENTS", position)) != std::string::npos) {
		result.replace(position, 10, joined);
		position += joined.size();
	}
	return result;
}

}
