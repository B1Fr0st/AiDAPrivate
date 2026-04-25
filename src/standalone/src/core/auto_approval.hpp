#pragma once

#include <string>
#include <vector>
#include <algorithm>
#include <cstdint>
#include <regex>
#include <functional>

#include <nlohmann/json.hpp>

#include "agent_registry.hpp"


namespace aida {
namespace permission {


struct rule_match_t
{
    enum class action_t : int
    {
        allow = 0,
        deny  = 1,
        ask   = 2
    };

    bool        matched = false;
    action_t    action = action_t::allow;
    std::string matched_pattern;
    std::string matched_permission_key;
};


inline bool wildcard_match(const std::string& pattern, const std::string& target)
{
    return aida::agent::wildcard_match(pattern, target);
}


inline rule_match_t evaluate(const aida::agent::ruleset_t& rules,
                             const std::string& permission_key,
                             const std::string& argument)
{
    rule_match_t out;
    out.matched = false;
    out.action = rule_match_t::action_t::allow;

    const aida::agent::permission_rule_t* match = nullptr;
    for (const auto& r : rules)
    {
        if (!wildcard_match(r.permission_key, permission_key))
            continue;
        if (!argument.empty() && !wildcard_match(r.pattern, argument))
            continue;
        match = &r;
    }

    if (match == nullptr)
        return out;

    out.matched = true;
    out.matched_pattern = match->pattern;
    out.matched_permission_key = match->permission_key;
    switch (match->action)
    {
    case aida::agent::permission_rule_t::action_t::allow:
        out.action = rule_match_t::action_t::allow; break;
    case aida::agent::permission_rule_t::action_t::deny:
        out.action = rule_match_t::action_t::deny; break;
    case aida::agent::permission_rule_t::action_t::ask:
        out.action = rule_match_t::action_t::ask; break;
    }
    return out;
}


inline std::string first_path_or_command_argument(const std::string& tool_name,
                                                   const nlohmann::json& args)
{
    if (!args.is_object()) return std::string{};

    const std::string key = aida::agent::permission_key_for_tool(tool_name);

    auto get_string = [&](std::initializer_list<const char*> names) -> std::string {
        for (const char* n : names)
        {
            if (args.contains(n) && args[n].is_string())
                return args[n].get<std::string>();
        }
        return std::string{};
    };

    if (key == "edit" || key == "read" ||
        key == "glob" || key == "list")
    {
        std::string v = get_string({"path", "file_path", "file", "filepath",
                                     "input_file", "target", "target_file",
                                     "directory"});
        if (!v.empty()) return v;
    }

    if (key == "bash")
    {
        std::string v = get_string({"command", "cmd", "shell", "bash",
                                     "command_text", "execute"});
        if (!v.empty()) return v;
    }

    if (key == "grep" || key == "codesearch")
    {
        std::string v = get_string({"path", "directory", "query", "pattern"});
        if (!v.empty()) return v;
    }

    if (key == "webfetch" || key == "websearch")
    {
        std::string v = get_string({"url", "query"});
        if (!v.empty()) return v;
    }

    if (key == "driver_write" || key == "driver_read")
    {
        std::string v = get_string({"address", "module", "process", "pattern"});
        if (!v.empty()) return v;
    }

    std::string fallback = get_string({"path", "file_path", "command", "url",
                                        "query", "name", "target"});
    return fallback;
}


}
}


namespace auto_approval {


struct settings_t
{
    bool always_allow_read_only              = false;
    bool always_allow_read_only_outside_ws   = false;
    bool always_allow_write                  = false;
    bool always_allow_write_outside_ws       = false;
    bool always_allow_write_protected        = false;
    bool always_allow_execute                = false;
    bool always_allow_mcp                    = false;
    bool always_allow_mode_switch            = true;
    bool always_allow_subtasks               = true;
    bool always_allow_followup               = false;

    int    max_requests = 0;
    double max_cost_usd = 0.0;

    std::string allowed_commands;
    std::string denied_commands;
};


struct task_counters_t
{
    int    auto_approved_requests = 0;
    double auto_approved_cost     = 0.0;

    void reset()
    {
        auto_approved_requests = 0;
        auto_approved_cost     = 0.0;
    }

    bool requests_exceeded(int max_requests) const
    {
        if (max_requests <= 0) return false;
        return auto_approved_requests >= max_requests;
    }

    bool cost_exceeded(double max_cost) const
    {
        if (max_cost <= 0.0) return false;
        return auto_approved_cost >= (max_cost - 1e-9);
    }
};


enum class tool_category_t
{
    read_only,
    write,
    execute,
    mcp,
    mode_switch,
    subtask,
    followup,
    always_auto
};


inline tool_category_t categorize_tool(const std::string& tool_name)
{
    if (tool_name == "switch_agent")
        return tool_category_t::mode_switch;
    if (tool_name == "task")
        return tool_category_t::subtask;
    if (tool_name == "ask_followup_question")
        return tool_category_t::followup;
    if (tool_name == "update_todo_list" || tool_name == "skill" ||
        tool_name == "get_tool_descriptions" || tool_name == "convert_number" ||
        tool_name == "attempt_completion")
        return tool_category_t::always_auto;

    if (tool_name == "execute_command" || tool_name == "sandbox_execute" ||
        tool_name == "read_command_output")
        return tool_category_t::execute;

    if (tool_name.size() > 5 && tool_name.substr(0, 5) == "mcp::")
        return tool_category_t::mcp;

    if (tool_name == "list_directory" || tool_name == "read_file" ||
        tool_name == "read_file_content" || tool_name == "search_files" ||
        tool_name == "get_file_info" || tool_name == "grep_in_files" ||
        tool_name == "codebase_search" || tool_name == "web_search" ||
        tool_name == "read_memory" || tool_name == "read_memory_string" ||
        tool_name == "disassemble_address" || tool_name == "disassemble_file" ||
        tool_name == "get_imports" || tool_name == "get_exports" ||
        tool_name == "get_sections" || tool_name == "get_pe_header" ||
        tool_name == "hex_dump" || tool_name == "hex_dump_file" ||
        tool_name == "list_checkpoints" || tool_name == "list_processes" ||
        tool_name == "list_modules" || tool_name == "list_threads" ||
        tool_name == "driver_status")
        return tool_category_t::read_only;

    return tool_category_t::write;
}


inline std::vector<std::string> split_csv(const std::string& csv)
{
    std::vector<std::string> result;
    std::string item;
    for (char c : csv) {
        if (c == ',') {
            auto trimmed = item;
            while (!trimmed.empty() && (trimmed.front() == ' ' || trimmed.front() == '\t'))
                trimmed.erase(trimmed.begin());
            while (!trimmed.empty() && (trimmed.back() == ' ' || trimmed.back() == '\t'))
                trimmed.pop_back();
            if (!trimmed.empty()) result.push_back(trimmed);
            item.clear();
        } else {
            item.push_back(c);
        }
    }
    if (!item.empty()) {
        auto trimmed = item;
        while (!trimmed.empty() && (trimmed.front() == ' ' || trimmed.front() == '\t'))
            trimmed.erase(trimmed.begin());
        while (!trimmed.empty() && (trimmed.back() == ' ' || trimmed.back() == '\t'))
            trimmed.pop_back();
        if (!trimmed.empty()) result.push_back(trimmed);
    }
    return result;
}


inline bool is_dangerous_command(const std::string& command)
{
    static const char* dangerous_patterns[] = {
        "rm -rf /",
        "rm -rf /*",
        "rmdir /s /q C:\\",
        "del /f /s /q C:\\",
        "format ",
        ":(){:|:&};:",
        "> /dev/sda",
        "dd if=/dev/zero of=/dev/",
        "mkfs.",
        "shutdown",
        "halt",
        "init 0",
        "init 6",
    };

    for (const char* pattern : dangerous_patterns) {
        if (command.find(pattern) != std::string::npos)
            return true;
    }

    static const char* shell_expansion_patterns[] = {
        "${!",
        "@P}",
        "@Q}",
        "@E}",
        "@A}",
        "@a}",
        "=(\\(",
        "<<<$(",
    };
    for (const char* pattern : shell_expansion_patterns) {
        if (command.find(pattern) != std::string::npos)
            return true;
    }

    return false;
}


inline bool command_matches_prefix(const std::string& command, const std::string& prefix)
{
    if (prefix == "*") return true;
    if (prefix.empty()) return false;

    if (prefix.back() == '*') {
        std::string base = prefix.substr(0, prefix.size() - 1);
        return command.compare(0, base.size(), base) == 0;
    }

    return command == prefix ||
           (command.size() > prefix.size() && command.compare(0, prefix.size(), prefix) == 0 &&
            (command[prefix.size()] == ' ' || command[prefix.size()] == '\t'));
}


enum class approval_decision_t
{
    approve,
    deny,
    ask_user
};


inline approval_decision_t check_command_approval(
    const std::string& command,
    const std::string& allowed_csv,
    const std::string& denied_csv)
{
    auto allowed = split_csv(allowed_csv);
    auto denied  = split_csv(denied_csv);

    std::string best_allow;
    std::string best_deny;

    for (auto& prefix : allowed) {
        if (command_matches_prefix(command, prefix)) {
            if (prefix.size() > best_allow.size() || (prefix == "*" && best_allow.empty()))
                best_allow = prefix;
        }
    }

    for (auto& prefix : denied) {
        if (command_matches_prefix(command, prefix)) {
            if (prefix.size() > best_deny.size() || (prefix == "*" && best_deny.empty()))
                best_deny = prefix;
        }
    }

    if (!best_deny.empty() && !best_allow.empty()) {
        if (best_deny == "*" && best_allow != "*")
            return approval_decision_t::approve;
        if (best_allow == "*" && best_deny != "*")
            return approval_decision_t::deny;
        return (best_allow.size() >= best_deny.size())
            ? approval_decision_t::approve
            : approval_decision_t::deny;
    }

    if (!best_deny.empty())
        return approval_decision_t::deny;

    if (!best_allow.empty())
        return approval_decision_t::approve;

    return approval_decision_t::ask_user;
}


inline approval_decision_t should_auto_approve(
    const std::string& tool_name,
    const settings_t& settings,
    const task_counters_t& counters,
    const std::string& command_text = "",
    bool file_outside_workspace = false,
    bool file_is_protected = false)
{
    if (counters.requests_exceeded(settings.max_requests))
        return approval_decision_t::ask_user;
    if (counters.cost_exceeded(settings.max_cost_usd))
        return approval_decision_t::ask_user;

    auto category = categorize_tool(tool_name);

    switch (category) {
    case tool_category_t::always_auto:
        return approval_decision_t::approve;

    case tool_category_t::mode_switch:
        return settings.always_allow_mode_switch
            ? approval_decision_t::approve
            : approval_decision_t::ask_user;

    case tool_category_t::subtask:
        return settings.always_allow_subtasks
            ? approval_decision_t::approve
            : approval_decision_t::ask_user;

    case tool_category_t::followup:
        return settings.always_allow_followup
            ? approval_decision_t::approve
            : approval_decision_t::ask_user;

    case tool_category_t::read_only:
        if (!settings.always_allow_read_only)
            return approval_decision_t::ask_user;
        if (file_outside_workspace && !settings.always_allow_read_only_outside_ws)
            return approval_decision_t::ask_user;
        return approval_decision_t::approve;

    case tool_category_t::write:
        if (!settings.always_allow_write)
            return approval_decision_t::ask_user;
        if (file_outside_workspace && !settings.always_allow_write_outside_ws)
            return approval_decision_t::ask_user;
        if (file_is_protected && !settings.always_allow_write_protected)
            return approval_decision_t::ask_user;
        return approval_decision_t::approve;

    case tool_category_t::execute:
    {
        if (!settings.always_allow_execute)
            return approval_decision_t::ask_user;

        if (!command_text.empty() && is_dangerous_command(command_text))
            return approval_decision_t::ask_user;

        if (!settings.allowed_commands.empty() || !settings.denied_commands.empty()) {
            auto cmd_decision = check_command_approval(
                command_text, settings.allowed_commands, settings.denied_commands);
            if (cmd_decision == approval_decision_t::deny)
                return approval_decision_t::deny;
            if (cmd_decision == approval_decision_t::ask_user)
                return approval_decision_t::ask_user;
        }
        return approval_decision_t::approve;
    }

    case tool_category_t::mcp:
        return settings.always_allow_mcp
            ? approval_decision_t::approve
            : approval_decision_t::ask_user;
    }

    return approval_decision_t::ask_user;
}


inline bool matches_aidaignore(
    const std::string& file_path,
    const std::vector<std::string>& ignore_patterns)
{
    if (ignore_patterns.empty()) return false;

    std::string normalized = file_path;
    std::replace(normalized.begin(), normalized.end(), '\\', '/');

    for (const auto& pattern : ignore_patterns) {
        if (pattern.empty() || pattern[0] == '#') continue;

        try {
            std::string regex_pattern = pattern;

            std::string escaped;
            for (char c : regex_pattern) {
                switch (c) {
                case '.': escaped += "\\."; break;
                case '?': escaped += "."; break;
                case '*':
                    if (!escaped.empty() && escaped.back() == '\\' &&
                        escaped.size() >= 2 && escaped[escaped.size() - 2] == '*') {
                        escaped.pop_back();
                        escaped += ".*";
                    } else {
                        escaped += "[^/]*";
                    }
                    break;
                case '(': case ')': case '[': case ']':
                case '{': case '}': case '+': case '^':
                case '$': case '|':
                    escaped.push_back('\\');
                    escaped.push_back(c);
                    break;
                default:
                    escaped.push_back(c);
                    break;
                }
            }

            std::regex re(escaped, std::regex_constants::icase);
            if (std::regex_search(normalized, re))
                return true;
        } catch (...) {
            if (normalized.find(pattern) != std::string::npos)
                return true;
        }
    }
    return false;
}


inline std::vector<std::string> load_aidaignore(const std::string& workspace_root)
{
    std::vector<std::string> patterns;
    std::string path = workspace_root;
    if (!path.empty() && path.back() != '\\' && path.back() != '/')
        path += '/';
    path += ".aidaignore";

    FILE* f = nullptr;
    fopen_s(&f, path.c_str(), "r");
    if (!f) return patterns;

    char line_buf[1024];
    while (fgets(line_buf, sizeof(line_buf), f)) {
        std::string line(line_buf);
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r' || line.back() == ' '))
            line.pop_back();
        while (!line.empty() && line.front() == ' ')
            line.erase(line.begin());
        if (!line.empty() && line[0] != '#')
            patterns.push_back(line);
    }
    fclose(f);
    return patterns;
}


}
