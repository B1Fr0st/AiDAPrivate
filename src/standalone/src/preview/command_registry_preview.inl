#include "../core/ai/command_registry.hpp"
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
	std::lock_guard<std::mutex> lock(preview_mutex());
	return preview_commands();
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
	std::lock_guard<std::mutex> lock(preview_mutex());
	const std::string needle = lower_ascii(query);
	std::vector<std::pair<int, command_t>> ranked;
	for (const auto& command : preview_commands()) {
		const std::string name = lower_ascii(command.name);
		const std::string description = lower_ascii(command.description);
		int score = 0;
		if (needle.empty()) score = 1;
		else if (name == needle) score = 1000;
		else if (name.rfind(needle, 0) == 0) score = 700;
		else if (name.find(needle) != std::string::npos) score = 500;
		else if (description.find(needle) != std::string::npos) score = 250;
		if (score > 0)
			ranked.emplace_back(score, command);
	}
	std::stable_sort(ranked.begin(), ranked.end(), [](const auto& lhs, const auto& rhs) {
		if (lhs.first != rhs.first) return lhs.first > rhs.first;
		return lhs.second.name < rhs.second.name;
	});
	if (limit < 0) limit = 0;
	std::vector<command_t> result;
	const std::size_t count = (std::min)(ranked.size(), static_cast<std::size_t>(limit));
	result.reserve(count);
	for (std::size_t i = 0; i < count; ++i)
		result.push_back(std::move(ranked[i].second));
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
