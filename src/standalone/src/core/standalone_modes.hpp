#pragma once

#include <string>
#include <vector>
#include <algorithm>
#include <map>
#include <regex>

namespace aida_modes {

enum class tool_group_t : int {
    read = 0,
    edit,
    command,
    mcp,
    driver,
    emulation,
    network,
    always_available,
    COUNT
};

inline const char* tool_group_name(tool_group_t g)
{
    switch (g) {
    case tool_group_t::read:              return "read";
    case tool_group_t::edit:              return "edit";
    case tool_group_t::command:           return "command";
    case tool_group_t::mcp:              return "mcp";
    case tool_group_t::driver:           return "driver";
    case tool_group_t::emulation:        return "emulation";
    case tool_group_t::network:          return "network";
    case tool_group_t::always_available: return "always_available";
    default:                             return "unknown";
    }
}

inline tool_group_t tool_group_from_name(const std::string& name)
{
    if (name == "read")              return tool_group_t::read;
    if (name == "edit")              return tool_group_t::edit;
    if (name == "command")           return tool_group_t::command;
    if (name == "mcp")              return tool_group_t::mcp;
    if (name == "driver")           return tool_group_t::driver;
    if (name == "emulation")        return tool_group_t::emulation;
    if (name == "network")          return tool_group_t::network;
    if (name == "always_available") return tool_group_t::always_available;
    return tool_group_t::read;
}

struct mode_config_t
{
    std::string slug;
    std::string display_name;
    std::string role_definition;
    std::string when_to_use;
    std::vector<tool_group_t> groups;
    std::string custom_instructions;
    std::vector<std::string> file_restrictions;
    bool is_custom = false;
};


inline const std::vector<std::string>& always_available_tools()
{
    static const std::vector<std::string> tools = {
        "get_tool_descriptions",
        "convert_number",
        "ask_followup_question",
        "attempt_completion",
        "switch_mode",
        "new_task",
        "update_todo_list",
        "run_slash_command",
        "skill",
    };
    return tools;
}


inline const std::map<std::string, std::string>& tool_aliases()
{
    static const std::map<std::string, std::string> aliases = {
        {"write_to_file", "write_file"},
        {"search_and_replace", "edit_file"},
        {"search_replace", "edit_file"},
        {"list_files", "list_directory"},
        {"read_file_content", "read_file"},
        {"write_file_content", "write_file"},
    };
    return aliases;
}


inline std::string resolve_tool_alias(const std::string& name)
{
    auto& aliases = tool_aliases();
    auto it = aliases.find(name);
    if (it != aliases.end()) return it->second;
    return name;
}


inline tool_group_t classify_tool(const std::string& name)
{
    auto& always = always_available_tools();
    if (std::find(always.begin(), always.end(), name) != always.end())
        return tool_group_t::always_available;

    if (name == "list_directory" || name == "read_file_content" ||
        name == "read_file" || name == "search_files" || name == "get_file_info" ||
        name == "read_memory" || name == "read_memory_string" ||
        name == "disassemble_address" || name == "disassemble_file" ||
        name == "get_imports" || name == "get_exports" ||
        name == "get_sections" || name == "get_pe_header" ||
        name == "hex_dump" || name == "hex_dump_file" ||
        name == "grep_in_files" || name == "codebase_search" ||
        name == "list_checkpoints" || name == "web_search")
        return tool_group_t::read;

    if (name == "write_file_content" || name == "write_file" ||
        name == "create_file" || name == "create_directory" ||
        name == "rename_path" || name == "delete_path" || name == "delete_file" ||
        name == "patch_bytes" || name == "write_memory" ||
        name == "edit_file" || name == "apply_diff" || name == "apply_patch" ||
        name == "save_checkpoint" || name == "restore_checkpoint")
        return tool_group_t::edit;

    if (name == "execute_command" || name == "sandbox_execute" ||
        name == "read_command_output")
        return tool_group_t::command;

    if (name == "driver_status" || name == "driver_load" ||
        name == "driver_attach" || name == "driver_detach" ||
        name == "list_processes" || name == "list_modules" ||
        name == "list_threads" || name == "find_pattern")
        return tool_group_t::driver;

    if (name == "emulate_code" || name == "emulate_function")
        return tool_group_t::emulation;

    if (name == "http_request" || name == "dns_lookup" ||
        name == "whois_lookup" || name == "check_ssl_cert" ||
        name == "check_domain_reputation")
        return tool_group_t::network;

    if (name.size() > 5 && name.substr(0, 5) == "mcp::")
        return tool_group_t::mcp;

    return tool_group_t::read;
}


inline const std::vector<mode_config_t>& builtin_modes()
{
    static const std::vector<mode_config_t> modes = {
        {
            "agent",
            "Agent",
            "You are AiDA, a state-of-the-art autonomous reverse engineering agent. "
            "You operate through a kernel-backed live process inspection bridge, "
            "Zydis for x64 disassembly, Unicorn for emulation, "
            "and Windows Sandbox for safe sample execution.\n"
            "You have full access to all tools. Use them proactively to accomplish tasks. "
            "When asked to analyze, disassemble, or inspect something, USE YOUR TOOLS. "
            "Do NOT fabricate tool results.",
            "Use this mode for complex, multi-step tasks that require full tool access.",
            {tool_group_t::read, tool_group_t::edit, tool_group_t::command,
             tool_group_t::mcp, tool_group_t::driver, tool_group_t::emulation,
             tool_group_t::network, tool_group_t::always_available},
            "", {}, false
        },
        {
            "code",
            "Code",
            "You are AiDA in Code mode. You are an expert code assistant specialized in "
            "reverse engineering, binary analysis, and systems programming. "
            "Focus on code editing, file operations, and analysis. "
            "You can read files, edit code, run commands, and use the driver for inspection.",
            "Use this mode for focused coding and file editing tasks.",
            {tool_group_t::read, tool_group_t::edit, tool_group_t::command,
             tool_group_t::driver, tool_group_t::always_available},
            "", {}, false
        },
        {
            "architect",
            "Architect",
            "You are AiDA in Architect mode. You are a system design expert focused on "
            "binary analysis planning, malware triage strategy, and reverse engineering workflows. "
            "You can read and analyze, but your edits are restricted to documentation files. "
            "Suggest approaches and explain reasoning. Write plans and architecture docs.",
            "Use this mode for planning, analysis strategy, and high-level guidance.",
            {tool_group_t::read, tool_group_t::edit, tool_group_t::mcp, tool_group_t::driver,
             tool_group_t::always_available},
            "", {"\\.md$", "\\.txt$", "\\.rst$"}, false
        },
        {
            "ask",
            "Ask",
            "You are AiDA in Ask mode. You are a knowledgeable assistant focused on "
            "answering questions, providing information, and explaining concepts. "
            "You can read files and search the codebase but you should NOT make any modifications. "
            "Focus on understanding, explaining, and informing.",
            "Use this mode for information retrieval, questions, and explanations without file modifications.",
            {tool_group_t::read, tool_group_t::mcp, tool_group_t::always_available},
            "", {}, false
        },
        {
            "debug",
            "Debug",
            "You are AiDA in Debug mode. You are a debugging specialist focused on "
            "live process inspection, memory analysis, crash diagnosis, and runtime debugging. "
            "You have full access to the kernel driver bridge and emulation engine. "
            "Focus on finding and diagnosing bugs, crashes, and anomalous behavior.",
            "Use this mode for debugging, crash analysis, and live process inspection.",
            {tool_group_t::read, tool_group_t::command, tool_group_t::driver,
             tool_group_t::emulation, tool_group_t::network, tool_group_t::always_available},
            "", {}, false
        },


        {
            "orchestrator",
            "Orchestrator",
            "You are AiDA in Orchestrator mode. You are a high-level task coordinator. "
            "Your role is to break down complex requests into subtasks and delegate them "
            "to the appropriate specialized modes (Agent, Code, Architect, Debug, Ask). "
            "You do NOT execute tools directly — you plan, decompose, and delegate via "
            "switch_mode and new_task. After delegating, review results and coordinate "
            "the next steps. Think of yourself as a project manager for reverse engineering workflows.",
            "Use this mode to coordinate complex multi-step projects across specialized modes.",
            {tool_group_t::always_available},
            "", {}, false
        },
    };
    return modes;
}


inline std::vector<mode_config_t>& custom_modes()
{
    static std::vector<mode_config_t> modes;
    return modes;
}


inline const mode_config_t* find_mode(const std::string& slug)
{
    for (auto& m : custom_modes()) {
        if (m.slug == slug) return &m;
    }
    for (auto& m : builtin_modes()) {
        if (m.slug == slug) return &m;
    }
    return nullptr;
}


inline bool mode_allows_tool(const mode_config_t& mode, const std::string& tool_name)
{
    auto resolved = resolve_tool_alias(tool_name);

    auto& always = always_available_tools();
    if (std::find(always.begin(), always.end(), resolved) != always.end())
        return true;

    tool_group_t group = classify_tool(resolved);
    for (auto g : mode.groups) {
        if (g == group) return true;
    }
    return false;
}


inline bool check_file_restriction(const mode_config_t& mode, const std::string& file_path)
{
    if (mode.file_restrictions.empty())
        return true;

    for (const auto& pattern : mode.file_restrictions) {
        try {
            std::regex re(pattern, std::regex_constants::icase);
            if (std::regex_search(file_path, re))
                return true;
        } catch (...) {
            if (file_path.size() >= pattern.size() &&
                file_path.compare(file_path.size() - pattern.size(), pattern.size(), pattern) == 0)
                return true;
        }
    }
    return false;
}


inline void add_custom_mode(const mode_config_t& mode)
{
    auto& customs = custom_modes();
    for (auto& m : customs) {
        if (m.slug == mode.slug) {
            m = mode;
            m.is_custom = true;
            return;
        }
    }
    mode_config_t copy = mode;
    copy.is_custom = true;
    customs.push_back(copy);
}

inline void remove_custom_mode(const std::string& slug)
{
    auto& customs = custom_modes();
    customs.erase(
        std::remove_if(customs.begin(), customs.end(),
                       [&slug](const mode_config_t& m) { return m.slug == slug; }),
        customs.end());
}

inline std::vector<const mode_config_t*> get_all_modes()
{
    std::vector<const mode_config_t*> result;
    std::vector<std::string> seen;

    for (auto& m : custom_modes()) {
        result.push_back(&m);
        seen.push_back(m.slug);
    }

    for (auto& m : builtin_modes()) {
        if (std::find(seen.begin(), seen.end(), m.slug) == seen.end())
            result.push_back(&m);
    }

    return result;
}


inline std::string active_mode_slug = "agent";

inline const mode_config_t& get_active_mode()
{
    const auto* m = find_mode(active_mode_slug);
    if (m) return *m;
    return builtin_modes().front();
}

inline void set_active_mode(const std::string& slug)
{
    if (find_mode(slug))
        active_mode_slug = slug;
}

}
