
#include <windows.h>
#include <intrin.h>

#include "work_queue.hpp"
#include "critical_work_queue.hpp"
#include "theme.hpp"
#include "mcp_standalone.hpp"
#include "mcp_client.hpp"
#include "mcp_marketplace.hpp"
#include "standalone_ai_client.hpp"
#include "standalone_license.hpp"
#include "standalone_settings.hpp"
#include "standalone_driver.hpp"
#include "agent_registry.hpp"
#include "agent_picker_view.hpp"
#include "binary_map.hpp"
#include "tool_repetition.hpp"
#include "standalone_tools_fwd.hpp"
#include "cost_calculator.hpp"
#include "compaction.hpp"
#include "command_registry.hpp"
#include "settings_overlay.hpp"
#include "session_store.hpp"
#include "auth_store.hpp"
#include "event_bus.hpp"
#include "auth_view.hpp"
#include "provider_view.hpp"
#include "agent_manager_view.hpp"
#include "skill_manager_view.hpp"
#include "binary_map_view.hpp"
#include "command_palette_view.hpp"
#include "provider_catalog.hpp"
#include "zydis_disasm.hpp"
#include "function_index.hpp"
#include "xref_index.hpp"
#include "initial_analysis.hpp"
#include "loading_binary_overlay.hpp"
#include "auto_approval.hpp"
#include "file_context_tracker.hpp"
#include "standalone_context.hpp"
#include "skills.hpp"
#include "../analysis/stealth_engine.hpp"
#include "../anti-tamper/mcp_posture.hpp"
#include "../anti-tamper/state.hpp"
#include "../testlab/test_all_features.hpp"
#include "../ui/components.hpp"
#include "../ui/fonts.hpp"

#include "../helpers/globals.h"
#include "../session/analysis_session.hpp"

#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <deque>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <map>
#include <exception>

#include <nlohmann/json.hpp>

#include "../helpers/diag_log.hpp"

using json = nlohmann::json;

extern DisasmState g_disasm;

mcp_client::manager_t s_mcp_client_mgr;


static file_context::tracker_t s_file_tracker;


static auto_approval::task_counters_t s_approval_counters;

namespace {

struct ai_update_t
{
    enum type_t { THINKING, CHUNK, COMPLETE, ERR } type;
    std::string text;
};

std::mutex              s_update_mtx;
std::deque<ai_update_t> s_updates;

void post_update(ai_update_t::type_t type, const std::string& text = {})
{
    std::lock_guard<std::mutex> lk(s_update_mtx);
    s_updates.push_back({type, text});
}


std::mutex        s_ai_thread_mtx;
std::atomic<bool> s_ai_running{false};
std::atomic<bool> s_cancel{false};
std::atomic<bool> s_ai_task_done{true};
std::mutex        s_ai_task_done_mtx;
std::condition_variable s_ai_task_done_cv;

std::mutex   s_chat_session_mtx;
std::string  s_chat_session_id;
std::string  s_chat_last_assistant_message_id;
int64_t      s_chat_used_tokens = 0;

std::string get_chat_session_id_locked()
{
    std::lock_guard<std::mutex> lk(s_chat_session_mtx);
    return s_chat_session_id;
}

void set_chat_session_id_locked(const std::string& sid)
{
    std::lock_guard<std::mutex> lk(s_chat_session_mtx);
    s_chat_session_id = sid;
    s_chat_used_tokens = 0;
    s_chat_last_assistant_message_id.clear();
}

void add_chat_used_tokens_locked(int64_t n)
{
    std::lock_guard<std::mutex> lk(s_chat_session_mtx);
    s_chat_used_tokens += n;
}

int64_t get_chat_used_tokens_locked()
{
    std::lock_guard<std::mutex> lk(s_chat_session_mtx);
    return s_chat_used_tokens;
}

void set_chat_last_assistant_message_id_locked(const std::string& mid)
{
    std::lock_guard<std::mutex> lk(s_chat_session_mtx);
    s_chat_last_assistant_message_id = mid;
}

std::string get_chat_last_assistant_message_id_locked()
{
    std::lock_guard<std::mutex> lk(s_chat_session_mtx);
    return s_chat_last_assistant_message_id;
}


mcp_standalone::server_t s_mcp_server;
bool                     s_server_started = false;
bool                     s_initialized    = false;
bool                     s_mcp_tools_registered = false;
std::atomic<bool>        s_ide_ready_for_mcp_services{false};


bool                  s_mcp_clients_connected = false;


struct tool_approval_t {
    std::mutex          mtx;
    std::condition_variable cv;
    bool                pending   = false;
    bool                approved  = false;
    bool                answered  = false;
    std::string         tool_name;
    std::string         tool_args_preview;
};
tool_approval_t s_tool_approval;

thread_local std::string t_tool_approval_deny_reason;

const std::string& tool_approval_last_deny_reason()
{
    return t_tool_approval_deny_reason;
}


std::string extract_tool_path_argument(const std::string& tool_name, const json& arguments)
{
    if (!arguments.is_object()) return std::string{};

    static const char* const path_keys[] = {
        "path", "file_path", "file", "filepath",
        "input_file", "target", "target_file", "directory",
        "destination", "output_path", "src", "dst"
    };
    for (const char* k : path_keys) {
        if (arguments.contains(k) && arguments[k].is_string()) {
            std::string v = arguments[k].get<std::string>();
            if (!v.empty()) return v;
        }
    }
    (void)tool_name;
    return std::string{};
}


std::string normalize_path_for_compare(const std::string& raw, bool prepend_workspace)
{
    if (raw.empty()) return raw;
    std::string p = raw;
    for (char& c : p) { if (c == '/') c = '\\'; }
    if (prepend_workspace &&
        !file_browser::current_dir.empty() && !p.empty() && p[0] != '\\' &&
        (p.size() < 2 || p[1] != ':')) {
        p = file_browser::current_dir + "\\" + p;
    }
    std::error_code ec;
    auto canonical = std::filesystem::weakly_canonical(std::filesystem::path(p), ec);
    if (ec) return p;
    return canonical.string();
}


bool tool_path_is_outside_workspace(const std::string& raw_path)
{
    if (raw_path.empty()) return false;
    if (file_browser::current_dir.empty()) return false;

    std::string canonical = normalize_path_for_compare(raw_path, true);
    if (canonical.empty()) return false;

    std::error_code ec;
    auto ws = std::filesystem::weakly_canonical(
        std::filesystem::path(file_browser::current_dir), ec);
    if (ec) return true;

    std::string ws_str = ws.string();
    auto to_lower = [](std::string& s) {
        std::transform(s.begin(), s.end(), s.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    };
    to_lower(ws_str);
    to_lower(canonical);
    return canonical.find(ws_str) != 0;
}


bool tool_path_is_protected(const std::string& raw_path)
{
    if (raw_path.empty()) return false;

    std::string lowered = raw_path;
    for (char& c : lowered) {
        if (c == '/') c = '\\';
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    static const char* const protected_substrings[] = {
        "\\.git\\",
        "\\.aida\\",
        "\\.claude\\",
        "\\.agents\\",
        "\\node_modules\\",
        "\\.ssh\\",
        "\\appdata\\roaming\\aida",
        "\\system32\\",
        "\\syswow64\\",
        "\\program files",
        "\\windows\\",
        "id_rsa",
        "id_ed25519",
        "aida_debug.log"
    };

    for (const char* s : protected_substrings) {
        if (lowered.find(s) != std::string::npos)
            return true;
    }

    auto ends_with = [](const std::string& s, const std::string& suf) {
        if (s.size() < suf.size()) return false;
        return s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
    };
    if (ends_with(lowered, "\\.env") || ends_with(lowered, ".env") ||
        ends_with(lowered, ".envrc") ||
        ends_with(lowered, ".pem")  || ends_with(lowered, ".pfx") ||
        ends_with(lowered, ".key")  || ends_with(lowered, ".p12")) {
        return true;
    }

    return false;
}

bool request_tool_approval(const std::string& name, const json& arguments)
{
    t_tool_approval_deny_reason.clear();

    {
        aida::agent::initialize();
        const aida::agent::agent_info_t* agent = aida::agent::active_agent();
        if (agent == nullptr)
            agent = aida::agent::get(aida::agent::default_agent_name());
        if (agent != nullptr) {
            const std::string permission_key = aida::agent::permission_key_for_tool(name);
            const std::string pattern_arg    = aida::permission::first_path_or_command_argument(name, arguments);

            auto eval_specific = aida::agent::evaluate_ruleset(
                agent->permissions, permission_key, pattern_arg);
            auto eval_tool = aida::agent::evaluate_ruleset(
                agent->permissions, name, pattern_arg);

            if (eval_specific == aida::agent::permission_rule_t::action_t::deny ||
                eval_tool     == aida::agent::permission_rule_t::action_t::deny) {
                t_tool_approval_deny_reason =
                    "Error: " + agent->name + " mode forbids this tool: " + name;
                return false;
            }
        }
    }

    if (g_sa_settings.tool_auto_approve)
        return true;


    if (!g_sa_settings.tool_always_allow.empty()) {
        std::istringstream ss(g_sa_settings.tool_always_allow);
        std::string tok;
        while (std::getline(ss, tok, ',')) {
            while (!tok.empty() && tok.front() == ' ') tok.erase(tok.begin());
            while (!tok.empty() && tok.back() == ' ') tok.pop_back();
            if (tok == name) return true;
        }
    }


    if (!g_sa_settings.tool_always_deny.empty()) {
        std::istringstream ss(g_sa_settings.tool_always_deny);
        std::string tok;
        while (std::getline(ss, tok, ',')) {
            while (!tok.empty() && tok.front() == ' ') tok.erase(tok.begin());
            while (!tok.empty() && tok.back() == ' ') tok.pop_back();
            if (tok == name) {
                t_tool_approval_deny_reason =
                    "Error: tool '" + name + "' is in the always-deny list.";
                return false;
            }
        }
    }


    {
        auto_approval::settings_t aa_settings;
        aa_settings.always_allow_read_only  = g_sa_settings.auto_approve_read;
        aa_settings.always_allow_write      = g_sa_settings.auto_approve_write;
        aa_settings.always_allow_execute    = g_sa_settings.auto_approve_execute;
        aa_settings.always_allow_mcp        = g_sa_settings.auto_approve_mcp;
        aa_settings.always_allow_mode_switch = g_sa_settings.auto_approve_mode_switch;
        aa_settings.always_allow_subtasks   = g_sa_settings.auto_approve_subtask;
        aa_settings.max_requests            = g_sa_settings.auto_approve_max_requests;
        aa_settings.max_cost_usd            = g_sa_settings.auto_approve_max_cost;


        aa_settings.allowed_commands = g_sa_settings.auto_approve_allowed_commands;


        if (arguments.contains("path") && arguments["path"].is_string()) {
            std::string path = arguments["path"].get<std::string>();
            auto ignore_patterns = auto_approval::load_aidaignore(g_sa_settings.aidaignore_path);
            if (auto_approval::matches_aidaignore(path, ignore_patterns)) {
                t_tool_approval_deny_reason =
                    "Error: path '" + path + "' is excluded by .aidaignore.";
                return false;
            }
        }


        std::string command;
        if (name == "execute_command" && arguments.contains("command") &&
            arguments["command"].is_string())
            command = arguments["command"].get<std::string>();

        const std::string arg_path = extract_tool_path_argument(name, arguments);
        const bool file_outside_workspace = tool_path_is_outside_workspace(arg_path);
        const bool file_is_protected      = tool_path_is_protected(arg_path);

        auto decision = auto_approval::should_auto_approve(
                name, aa_settings, s_approval_counters, command,
                file_outside_workspace, file_is_protected);
        if (decision == auto_approval::approval_decision_t::approve)
            return true;
        if (decision == auto_approval::approval_decision_t::deny) {
            t_tool_approval_deny_reason =
                "Error: auto-approval policy denied tool '" + name + "'.";
            return false;
        }
    }


    {
        std::lock_guard<std::mutex> lk(s_tool_approval.mtx);
        s_tool_approval.tool_name = name;
        try { s_tool_approval.tool_args_preview = arguments.dump(2).substr(0, 500); }
        catch (...) { s_tool_approval.tool_args_preview = "(unable to display)"; }
        s_tool_approval.pending = true;
        s_tool_approval.answered = false;
        s_tool_approval.approved = false;
    }

    std::unique_lock<std::mutex> lk(s_tool_approval.mtx);
    s_tool_approval.cv.wait(lk, [] { return s_tool_approval.answered || s_cancel.load(); });
    s_tool_approval.pending = false;
    if (s_cancel.load()) return false;
    return s_tool_approval.approved;
}


enum class tool_repetition_decision_t
{
    none,
    warn,
    force_ask
};

tool_repetition_decision_t note_tool_repetition(
    const std::string& tool_name,
    const json& arguments,
    std::string& out_message)
{
    out_message.clear();

    std::string args_json;
    try { args_json = arguments.dump(); }
    catch (...) { args_json.clear(); }

    auto& detector = workflow_tools::get_repetition_detector();
    detector.record(tool_name, args_json);

    if (detector.should_force_ask()) {
        out_message = detector.warning_message();
        return tool_repetition_decision_t::force_ask;
    }
    if (detector.should_warn()) {
        out_message = detector.warning_message();
        return tool_repetition_decision_t::warn;
    }
    return tool_repetition_decision_t::none;
}


struct parsed_tool_call_t
{
    std::string name;
    json        arguments;
};

std::vector<parsed_tool_call_t> parse_tool_calls(const std::string& text)
{
    std::vector<parsed_tool_call_t> calls;
    const std::string open_tag  = "<tool_call>";
    const std::string close_tag = "</tool_call>";

    size_t pos = 0;
    while (pos < text.size()) {
        size_t start = text.find(open_tag, pos);
        if (start == std::string::npos) break;
        size_t body_start = start + open_tag.size();
        size_t end = text.find(close_tag, body_start);
        if (end == std::string::npos) break;

        std::string payload = text.substr(body_start, end - body_start);

        while (!payload.empty() && (payload.front() == ' ' || payload.front() == '\n' ||
               payload.front() == '\r' || payload.front() == '\t'))
            payload.erase(0, 1);
        while (!payload.empty() && (payload.back() == ' ' || payload.back() == '\n' ||
               payload.back() == '\r' || payload.back() == '\t'))
            payload.pop_back();

        auto j = json::parse(payload, nullptr, false);
        if (!j.is_discarded() && j.is_object()) {
            parsed_tool_call_t tc;
            tc.name      = j.value("name", "");
            tc.arguments = j.value("arguments", json::object());
            if (!tc.name.empty())
                calls.push_back(std::move(tc));
        }

        pos = end + close_tag.size();
    }
    return calls;
}

std::string strip_tool_blocks(const std::string& text)
{
    std::string result;
    const std::string open_tag  = "<tool_call>";
    const std::string close_tag = "</tool_call>";
    const std::string open_res  = "<tool_result";
    const std::string close_res = "</tool_result>";

    size_t pos = 0;
    while (pos < text.size()) {

        size_t tc_start = text.find(open_tag, pos);
        size_t tr_start = text.find(open_res, pos);
        size_t next_tag = (std::min)(tc_start, tr_start);

        if (next_tag == std::string::npos) {
            result += text.substr(pos);
            break;
        }

        result += text.substr(pos, next_tag - pos);

        if (next_tag == tc_start) {
            size_t end = text.find(close_tag, tc_start);
            pos = (end != std::string::npos) ? end + close_tag.size() : text.size();
        } else {
            size_t end = text.find(close_res, tr_start);
            pos = (end != std::string::npos) ? end + close_res.size() : text.size();
        }
    }


    while (!result.empty() && (result.front() == '\n' || result.front() == '\r'))
        result.erase(0, 1);
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();
    return result;
}


std::string build_system_prompt(bool force_xml_fallback = false)
{
    std::string prompt;
    prompt.reserve(16384);

    aida::agent::initialize();
    const aida::agent::agent_info_t* agent = aida::agent::active_agent();
    if (agent == nullptr)
        agent = aida::agent::get(aida::agent::default_agent_name());

    if (agent != nullptr) {
        prompt += agent->system_prompt;
        prompt += "\n\n";
    }

    {
        bool attached = driver_bridge::attached_pid() != 0;
        std::vector<std::string> empty_groups;
        std::string display = (agent != nullptr) ? agent->name : std::string("build");
        std::string env_details = file_context::build_environment_details(
            g_sa_settings.workspace.root_path,
            display,
            attached,
            attached ? driver_bridge::attached_process_name() : "",
            attached ? driver_bridge::attached_pid() : 0,
            empty_groups);
        prompt += env_details + "\n";
    }

    {
        auto sessions = analysis_session::list_session_summaries();
        if (!sessions.empty()) {
            prompt += "## Open analysis sessions\n";
            prompt += "Multiple targets are open. Every MCP tool accepts an optional `binary_id` parameter to route the call. When omitted the active session is used. Switch with `sessions_switch`.\n\n";
            for (const auto& s : sessions) {
                char line[512];
                if (s.kind == analysis_session::session_kind_t::live_attach) {
                    std::snprintf(line, sizeof(line),
                        "- [%s] live  pid=%u  %s  %s\n",
                        s.id.c_str(),
                        s.pid,
                        s.process_name.empty() ? s.filename.c_str() : s.process_name.c_str(),
                        s.is_active ? "(active)" : "");
                } else {
                    std::snprintf(line, sizeof(line),
                        "- [%s] file  %s  %s\n",
                        s.id.c_str(),
                        s.path.c_str(),
                        s.is_active ? "(active)" : "");
                }
                prompt += line;
            }
            prompt += "\n";
        }
    }

    if (agent != nullptr && !agent->hidden &&
        (agent->mode == aida::agent::agent_info_t::mode_t::primary ||
         agent->mode == aida::agent::agent_info_t::mode_t::all)) {
        std::string injected = aida::binary_map::auto_inject_text(4096);
        if (!injected.empty()) {
            prompt += "## Binary Map (auto-generated)\n";
            prompt += injected;
            prompt += "\n\n";
        }
    }

    prompt +=
        "## Available Tools\n"
        "Below is the list of all tool names you can call. To learn a tool's parameters "
        "and description before using it, call `get_tool_descriptions` with the tool names you need.\n\n";
    prompt +=
        "For simple visible browser tasks, use `camoufox_open_url` directly with a fully-qualified URL. "
        "Do not call `driver_status`, `check_environment`, `launch_browser`, or separate `navigate` first unless diagnostics or advanced browser instrumentation are needed.\n\n";

    {
        auto& tools = s_mcp_server.get_tools();
        for (const auto& t : tools)
            prompt += "- " + t.name + "\n";
    }

    auto remote_tools = s_mcp_client_mgr.get_all_tools();
    if (!remote_tools.empty()) {
        prompt += "\n**External MCP Tools:**\n";
        for (const auto& rt : remote_tools)
            prompt += "- mcp::" + rt.name + " (from " + rt.server_name + ")\n";
    }
    prompt += "\n";

    if (force_xml_fallback) {
        prompt +=
            "## How to call a tool\n\n"
            "When you need to call a tool, output EXACTLY this format (one call per block):\n\n"
            "<tool_call>\n"
            "{\"name\": \"TOOL_NAME\", \"arguments\": {\"PARAM\": \"VALUE\"}}\n"
            "</tool_call>\n\n"
            "After each tool call you will receive its result inside <tool_result> tags.\n"
            "You may make multiple tool calls in sequence across turns.\n"
            "When you are done using tools, provide your final analysis as plain text "
            "WITHOUT any <tool_call> tags.\n";
    }

    return prompt;
}


std::string execute_tool(const std::string& raw_name, const json& arguments)
{
    static const std::map<std::string, std::string> alias_map = {
        {"write_to_file",      "write_file"},
        {"search_and_replace", "edit_file"},
        {"search_replace",     "edit_file"},
        {"list_files",         "list_directory"},
        {"read_file_content",  "read_file"},
        {"write_file_content", "write_file"},
    };
    std::string name = raw_name;
    {
        auto it = alias_map.find(raw_name);
        if (it != alias_map.end()) name = it->second;
    }

    (void)standalone_license::verify_entitlement_state();
    {
        std::string lifecycle_reason;
        if (!mcp_standalone::lifecycle_authorized(&lifecycle_reason)) {
            diag::log_tagged_fmt("mcp_standalone",
                "local_tool_dispatch_blocked tool='%s' reason='%.160s'",
                name.c_str(),
                lifecycle_reason.c_str());
            return "Error: AiDA MCP is not authorized. Open AiDAStandalone.exe, authenticate, and wait for the protected runtime to finish loading.";
        }
    }

    output_log::push(bottom_tab_t::mcp_log, "[tool] Executing: " + name);


    s_approval_counters.auto_approved_requests++;


    if (arguments.contains("path") && arguments["path"].is_string()) {
        std::string path = arguments["path"].get<std::string>();
        bool is_edit_tool = (name == "write_file" || name == "edit_file" || name == "create_file" ||
                             name == "delete_file" || name == "patch_bytes" || name == "apply_diff" ||
                             name == "apply_patch" || name == "save_checkpoint" || name == "restore_checkpoint");
        bool is_read_tool = (name == "read_file" || name == "list_directory" || name == "search_files" ||
                             name == "grep_in_files" || name == "codebase_search" || name == "hex_dump" ||
                             name == "hex_dump_file");
        if (is_edit_tool) {
            s_file_tracker.record_ai_edit(path);
        } else if (is_read_tool) {
            s_file_tracker.record_read(path);
        }
    }

    {
        const aida::agent::agent_info_t* agent = aida::agent::active_agent();
        if (agent != nullptr) {
            if (!aida::agent::tool_allowed(*agent, name)) {
                return std::string("Error: agent '") + agent->name +
                    "' does not permit tool '" + name + "'. "
                    "Switch to an agent that allows this tool (e.g. 'build') via switch_agent.";
            }

            const std::string permission_key = aida::agent::permission_key_for_tool(name);
            const std::string arg = aida::permission::first_path_or_command_argument(name, arguments);

            aida::permission::rule_match_t deny_match;
            deny_match.matched = false;

            auto m_name = aida::permission::evaluate(agent->permissions, name, arg);
            if (m_name.matched && m_name.action == aida::permission::rule_match_t::action_t::deny)
                deny_match = m_name;

            if (!deny_match.matched && permission_key != name) {
                auto m_key = aida::permission::evaluate(agent->permissions, permission_key, arg);
                if (m_key.matched && m_key.action == aida::permission::rule_match_t::action_t::deny)
                    deny_match = m_key;
            }

            if (deny_match.matched) {
                std::string err = std::string("Error: agent '") + agent->name +
                    "' forbids tool '" + name + "' (matched rule: " +
                    deny_match.matched_permission_key + " " + deny_match.matched_pattern + ")";
                if (agent->name == "plan") {
                    err += ". Plan mode is read-only - call plan_exit to switch to the build agent.";
                }
                output_log::push(bottom_tab_t::output, "[agent] hard-deny: " + name +
                    " (rule " + deny_match.matched_permission_key + " " + deny_match.matched_pattern + ")");
                return err;
            }
        }
    }

    if (name == "get_tool_descriptions") {
        std::string result;
        json names_arr;
        if (arguments.contains("names") && arguments["names"].is_array())
            names_arr = arguments["names"];
        else if (arguments.contains("names") && arguments["names"].is_string()) {
            names_arr = json::array();
            names_arr.push_back(arguments["names"].get<std::string>());
        }

        auto& tools = s_mcp_server.get_tools();
        auto remote_tools = s_mcp_client_mgr.get_all_tools();

        for (const auto& req_name : names_arr) {
            std::string n = req_name.get<std::string>();
            bool found = false;


            for (const auto& t : tools) {
                if (t.name == n) {
                    result += "### " + t.name + "\n" + t.description + "\n";
                    if (!t.params.empty()) {
                        result += "Parameters:\n";
                        for (const auto& p : t.params) {
                            result += "- `" + p.name + "` (" + p.type;
                            if (p.required) result += ", required";
                            result += "): " + p.description + "\n";
                        }
                    }
                    result += "\n";
                    found = true;
                    break;
                }
            }


            if (!found) {
                for (const auto& rt : remote_tools) {
                    if (("mcp::" + rt.name) == n || rt.name == n) {
                        result += "### mcp::" + rt.name + " (from " + rt.server_name + ")\n";
                        if (rt.description.empty() && !rt.original_name.empty()) {
                            json detail_args = {
                                {"names", json::array({rt.original_name})}
                            };
                            auto detail = s_mcp_client_mgr.call_tool(rt.server_name + "::get_tool_descriptions", detail_args);
                            if (detail.success && !detail.text.empty()) {
                                result += detail.text + "\n";
                                found = true;
                                break;
                            }
                        }
                        result += rt.description + "\n";
                        if (rt.input_schema.contains("properties") && rt.input_schema["properties"].is_object()) {
                            result += "Parameters:\n";
                            for (auto it = rt.input_schema["properties"].begin();
                                 it != rt.input_schema["properties"].end(); ++it) {
                                result += "- `" + it.key() + "` (";
                                result += it.value().value("type", "string");
                                result += "): " + it.value().value("description", "") + "\n";
                            }
                        }
                        result += "\n";
                        found = true;
                        break;
                    }
                }
            }

            if (!found)
                result += "### " + n + "\nError: Unknown tool.\n\n";
        }
        if (result.empty()) result = "No tool names provided. Pass {\"names\": [\"tool1\", \"tool2\"]}.";
        return result;
    }


    if (name.size() > 5 && name.substr(0, 5) == "mcp::") {
        std::string remote_name = name.substr(5);
        output_log::push(bottom_tab_t::mcp_log, "[mcp-client] -> " + remote_name);
        auto result = s_mcp_client_mgr.call_tool(remote_name, arguments);
        output_log::push(bottom_tab_t::mcp_log, std::string("[mcp-client] <- ") + (result.success ? "OK" : "ERR: " + result.text.substr(0, 120)));
        std::string output = result.text;
        if (!result.data.is_null() && !result.data.empty()) {
            if (!output.empty()) output += "\n";
            try { output += result.data.dump(2); } catch (...) {}
        }
        if (output.size() > 12000) {
            output.resize(12000);
            output += "\n... (output truncated to 12000 chars)";
        }
        {
            size_t pos = 0;
            while ((pos = output.find("<tool_call>", pos)) != std::string::npos)
                output.replace(pos, 11, "&lt;tool_call&gt;");
            pos = 0;
            while ((pos = output.find("</tool_call>", pos)) != std::string::npos)
                output.replace(pos, 12, "&lt;/tool_call&gt;");
            pos = 0;
            while ((pos = output.find("<tool_result", pos)) != std::string::npos)
                output.replace(pos, 12, "&lt;tool_result");
            pos = 0;
            while ((pos = output.find("</tool_result>", pos)) != std::string::npos)
                output.replace(pos, 14, "&lt;/tool_result&gt;");
        }
        if (!result.success && output.empty())
            output = "Error: MCP tool call failed.";
        return output;
    }


    auto& tools = s_mcp_server.get_tools();
    for (const auto& t : tools) {
        if (t.name == name) {
            mcp_standalone::tool_result_t tr;
            auto t_start = std::chrono::steady_clock::now();
            std::string scope_err;
            std::string scope_id_used;
            bool scope_swapped = false;
            {
                static std::recursive_mutex s_dispatch_mtx;
                std::lock_guard<std::recursive_mutex> dlk(s_dispatch_mtx);
                mcp_standalone::target_scope_t scope =
                    mcp_standalone::resolve_target(arguments, &scope_err);
                if (!scope.ok) {
                    diag::log_tagged_fmt("mcp_standalone",
                        "dispatch tool='%s' resolve_failed err='%s'",
                        name.c_str(), scope_err.c_str());
                    return std::string("Error: ") + scope_err;
                }
                scope_id_used = scope.resolved_id;
                scope_swapped = scope.swapped;
                try {
                    tr = t.handler(arguments);
                } catch (const std::exception& e) {
                    diag::log_tagged_fmt("mcp_standalone",
                        "dispatch tool='%s' exception='%s'", name.c_str(), e.what());
                    return std::string("Error: ") + e.what();
                } catch (...) {
                    diag::log_tagged_fmt("mcp_standalone",
                        "dispatch tool='%s' unknown_exception", name.c_str());
                    return "Error: Unknown exception executing tool.";
                }
            }
            auto t_end = std::chrono::steady_clock::now();
            auto dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
            diag::log_tagged_fmt("mcp_standalone",
                "dispatch tool='%s' binary_id='%s' swapped=%d ok=%d duration_ms=%lld",
                name.c_str(),
                scope_id_used.c_str(),
                scope_swapped ? 1 : 0,
                tr.success ? 1 : 0,
                static_cast<long long>(dur_ms));
            std::string output = tr.text;
            if (!tr.data.is_null() && !tr.data.empty()) {
                if (!output.empty()) output += "\n";
                try { output += tr.data.dump(2); } catch (...) {}
            }
            if (output.size() > 12000) {
                output.resize(12000);
                output += "\n... (output truncated to 12000 chars)";
            }
            return output;
        }
    }
    return "Error: Unknown tool '" + name + "'. Use the tools/list to see available tools.";
}


void run_agentic(std::string user_message,
                 std::vector<std::pair<std::string, std::string>> history)
{

    s_approval_counters = auto_approval::task_counters_t{};

    workflow_tools::get_repetition_detector().reset();

    diag::log_tagged_fmt("chat",
        "run_agentic_enter provider=%.40s model=%.80s user_len=%zu history=%zu",
        g_sa_settings.selected_provider_id().c_str(),
        g_sa_settings.selected_model_id().c_str(),
        user_message.size(),
        history.size());

    {
        uint64_t gate = standalone_license::inline_gate_check(
            standalone_license::gate_chat_pre_agentic);
        const double v = standalone_license::verify_gate_token(
            standalone_license::gate_chat_pre_agentic, gate);
        if (v < 0.5) {
            diag::log_tagged_fmt("chat",
                "run_agentic_pre_agentic_gate_blocked gt=0x%016llX v=%.3f",
                static_cast<unsigned long long>(gate), v);
            post_update(ai_update_t::ERR,
                standalone_license::decode_status_string(
                    standalone_license::str_session_revoked));
            return;
        }
    }

    if (!standalone_license::is_valid()) {
        diag::log_tagged("chat", "run_agentic_license_invalid");
        post_update(ai_update_t::ERR, "Session expired. Please restart.");
        return;
    }

    post_update(ai_update_t::THINKING);
    output_log::push(bottom_tab_t::output, "[ai] New request: " + user_message.substr(0, 120) + (user_message.size() > 120 ? "..." : ""));

    const bool force_xml = g_sa_settings.force_xml_tools;
    std::string system_prompt = build_system_prompt(force_xml);

    const int max_turns = (std::max)(g_sa_settings.max_agentic_rounds, 1);
    int64_t budget_used = 0;


    if (force_xml) {

        std::string conversation;
        conversation.reserve(4096);
        if (!history.empty()) {
            conversation += "## Previous conversation\n\n";
            for (auto& [role, text] : history)
                conversation += role + ": " + text + "\n\n";
        }
        conversation += "User: " + user_message + "\n\nAssistant:";

        std::string full_prompt = system_prompt + "\n\n" + conversation;

        for (int turn = 0; turn < max_turns; ++turn) {
            if (s_cancel.load()) {
                post_update(ai_update_t::COMPLETE);
                return;
            }


            if (standalone_license::inline_proof_check_a() < 0.5) {
                post_update(ai_update_t::ERR, "Service degraded. Please restart the application.");
                return;
            }

            if (turn > 0)
                post_update(ai_update_t::THINKING, "Processing tool results...");

            int64_t pre_in = cost_tracking::session_input_tokens;
            int64_t pre_out = cost_tracking::session_output_tokens;

            std::string response;
            try {
                response = g_sa_ai_client->chat_blocking(full_prompt, {}, nullptr, nullptr);
            } catch (const std::exception& e) {
                output_log::push(bottom_tab_t::output, std::string("[ai] Exception: ") + e.what());
                post_update(ai_update_t::ERR, std::string("Exception: ") + e.what());
                return;
            }


            budget_used += (cost_tracking::session_input_tokens - pre_in) +
                           (cost_tracking::session_output_tokens - pre_out);

            if (s_cancel.load()) {
                post_update(ai_update_t::COMPLETE);
                return;
            }

            if (response.size() >= 6 && response.substr(0, 6) == "Error:") {
                post_update(ai_update_t::ERR, response);
                return;
            }


            {
                uint64_t gate = standalone_license::inline_gate_check(
                    standalone_license::gate_chat_post_response);
                if (standalone_license::verify_gate_token(
                        standalone_license::gate_chat_post_response, gate) < 0.5) {
                    post_update(ai_update_t::ERR,
                        standalone_license::decode_status_string(
                            standalone_license::str_session_revoked));
                    return;
                }
            }

            std::string thinking_content;
            std::string clean_response = response;
            {
                const std::string think_start = "\x01THINK:";
                const std::string think_end = "\x01ENDTHINK\n";
                size_t ts = clean_response.find(think_start);
                if (ts != std::string::npos) {
                    size_t te = clean_response.find(think_end, ts);
                    if (te != std::string::npos) {
                        thinking_content = clean_response.substr(ts + think_start.size(),
                                                                  te - ts - think_start.size());
                        clean_response.erase(ts, te + think_end.size() - ts);
                    }
                }

                size_t p = 0;
                while ((p = clean_response.find(think_start, p)) != std::string::npos) {
                    size_t end = clean_response.find('\n', p + think_start.size());
                    if (end == std::string::npos) end = clean_response.size();
                    thinking_content += clean_response.substr(p + think_start.size(), end - p - think_start.size());
                    clean_response.erase(p, end - p + (end < clean_response.size() ? 1 : 0));
                }
            }

            if (!thinking_content.empty())
                post_update(ai_update_t::THINKING, thinking_content);

            auto calls = parse_tool_calls(clean_response);

            if (calls.empty()) {
                std::string clean = strip_tool_blocks(clean_response);
                if (clean.empty()) clean = clean_response;

                constexpr size_t CHARS_PER_CHUNK = 24;
                for (size_t i = 0; i < clean.size() && !s_cancel.load(); ) {
                    size_t n = (std::min)(CHARS_PER_CHUNK, clean.size() - i);
                    post_update(ai_update_t::CHUNK, clean.substr(i, n));
                    i += n;
                    std::this_thread::sleep_for(std::chrono::milliseconds(12));
                }
                post_update(ai_update_t::COMPLETE);
                return;
            }

            std::string tool_results;
            for (auto& tc : calls) {
                if (s_cancel.load()) {
                    post_update(ai_update_t::COMPLETE);
                    return;
                }
                post_update(ai_update_t::THINKING, "Calling " + tc.name + "...");

                {
                    uint64_t gate = standalone_license::inline_gate_check(
                        standalone_license::gate_chat_tool_exec);
                    if (!standalone_license::verify_tool_runtime(
                            standalone_license::gate_chat_tool_exec, gate, tc.name)) {
                        tool_results += "\n<tool_result name=\"" + tc.name + "\">\nService unavailable.\n</tool_result>\n";
                        continue;
                    }
                }

                if (!standalone_license::inline_proof_check_d()) {
                    tool_results += "\n<tool_result name=\"" + tc.name + "\">\nError: Tool execution timed out.\n</tool_result>\n";
                    continue;
                }

                if (!request_tool_approval(tc.name, tc.arguments)) {
                    const std::string& deny_reason = tool_approval_last_deny_reason();
                    const std::string  deny_text   = deny_reason.empty()
                        ? std::string("Tool execution denied by user.")
                        : deny_reason;
                    tool_results += "\n<tool_result name=\"" + tc.name + "\">\n"
                                  + deny_text
                                  + "\n</tool_result>\n";
                    continue;
                }

                std::string result = execute_tool(tc.name, tc.arguments);

                std::string repetition_msg;
                const auto rep_decision =
                    note_tool_repetition(tc.name, tc.arguments, repetition_msg);
                if (rep_decision != tool_repetition_decision_t::none && !repetition_msg.empty()) {
                    post_update(ai_update_t::THINKING, repetition_msg);
                    output_log::push(bottom_tab_t::output,
                        "[ai] repetition detector: " + repetition_msg);
                    if (rep_decision == tool_repetition_decision_t::force_ask &&
                        tc.name != "ask_followup_question") {
                        result += "\n\n[repetition guard] " + repetition_msg;
                    }
                }

                tool_results += "\n<tool_result name=\"" + tc.name + "\">\n"
                              + result
                              + "\n</tool_result>\n";
            }

            full_prompt += " " + clean_response + "\n"
                         + tool_results
                         + "\nContinue your analysis using the tool results above. "
                           "If you need more data, call more tools. "
                           "Otherwise, provide your final answer as plain text.\n\nAssistant:";
        }

        output_log::push(bottom_tab_t::output, "[ai] Reached max tool rounds (" + std::to_string(max_turns) + ") [xml]");
        post_update(ai_update_t::ERR, "Reached maximum tool-calling rounds (" + std::to_string(max_turns) + "). Stopping.");
        return;
    }


    json messages = json::array();
    {
        std::string sid_for_slice = get_chat_session_id_locked();
        bool used_compaction_slice = false;
        if (!sid_for_slice.empty()) {
            std::vector<aida::session::message_t> persisted;
            if (aida::session::list_messages(sid_for_slice, persisted, -1)) {
                std::string compaction_summary;
                std::string tail_start_id;
                for (auto rit = persisted.rbegin(); rit != persisted.rend(); ++rit) {
                    bool found = false;
                    for (const auto& part : rit->parts) {
                        if (part.kind == aida::session::part_t::kind_t::compaction
                            && !part.compaction.summary_text.empty()) {
                            compaction_summary = part.compaction.summary_text;
                            tail_start_id      = part.compaction.tail_start_message_id;
                            found              = true;
                            break;
                        }
                    }
                    if (found) break;
                }

                if (!compaction_summary.empty()) {
                    std::string synth_text;
                    synth_text.reserve(compaction_summary.size() + 96);
                    synth_text += "<previous_session_summary>\n";
                    synth_text += compaction_summary;
                    synth_text += "\n</previous_session_summary>";
                    messages.push_back({{"role", "user"}, {"content", synth_text}});

                    const bool has_tail = !tail_start_id.empty();
                    bool tail_active = false;
                    for (const auto& m : persisted) {
                        if (!has_tail) break;
                        if (!tail_active) {
                            if (m.id == tail_start_id) tail_active = true;
                            else continue;
                        }
                        bool has_compaction_part = false;
                        std::string flat;
                        flat.reserve(256);
                        for (const auto& part : m.parts) {
                            switch (part.kind) {
                                case aida::session::part_t::kind_t::text:
                                    if (!part.text.text.empty()) {
                                        if (!flat.empty()) flat += '\n';
                                        flat += part.text.text;
                                    }
                                    break;
                                case aida::session::part_t::kind_t::tool: {
                                    if (!flat.empty()) flat += '\n';
                                    flat += "[tool ";
                                    flat += part.tool.tool_name;
                                    flat += "] ";
                                    if (!part.tool.arguments.is_null()) {
                                        try { flat += part.tool.arguments.dump(); }
                                        catch (...) {}
                                    }
                                    if (!part.tool.output_text.empty()) {
                                        flat += "\n[output] ";
                                        flat += part.tool.output_text;
                                    }
                                    if (!part.tool.error_message.empty()) {
                                        flat += "\n[error] ";
                                        flat += part.tool.error_message;
                                    }
                                    break;
                                }
                                case aida::session::part_t::kind_t::reasoning:
                                    break;
                                case aida::session::part_t::kind_t::compaction:
                                    has_compaction_part = true;
                                    break;
                                case aida::session::part_t::kind_t::step_finish:
                                case aida::session::part_t::kind_t::step_start:
                                    break;
                                case aida::session::part_t::kind_t::file:
                                    if (!flat.empty()) flat += '\n';
                                    flat += "[file ";
                                    flat += part.file.mime;
                                    if (!part.file.filename.empty()) {
                                        flat += ' ';
                                        flat += part.file.filename;
                                    }
                                    flat += "]";
                                    break;
                            }
                        }
                        if (has_compaction_part) continue;
                        if (flat.empty()) continue;
                        std::string r;
                        switch (m.role) {
                            case aida::session::message_t::role_t::assistant:   r = "assistant"; break;
                            case aida::session::message_t::role_t::tool_result: r = "user";      break;
                            case aida::session::message_t::role_t::user:
                            default:                                            r = "user";      break;
                        }
                        messages.push_back({{"role", r}, {"content", flat}});
                    }
                    used_compaction_slice = true;
                }
            }
        }
        if (!used_compaction_slice) {
            for (auto& [role, text] : history) {
                std::string r = (role == "assistant" || role == "Assistant") ? "assistant" : "user";
                messages.push_back({{"role", r}, {"content", text}});
            }
        }
    }
    messages.push_back({{"role", "user"}, {"content", user_message}});


    auto& local_tools = s_mcp_server.get_tools();

    for (int turn = 0; turn < max_turns; ++turn) {
        if (s_cancel.load()) { post_update(ai_update_t::COMPLETE); return; }

        if (standalone_license::inline_proof_check_a() < 0.5) {
            post_update(ai_update_t::ERR, "Service degraded. Please restart the application.");
            return;
        }


        {
            std::string active_model = g_sa_settings.get_active_model();
            auto& model_info = context_mgmt::get_model_info(active_model);
            int ctx_window = model_info.context_window;

            int estimated_tokens = 0;
            for (auto& m : messages) {
                std::string content_str;
                if (m.contains("content")) {
                    if (m["content"].is_string())
                        content_str = m["content"].get<std::string>();
                    else if (m["content"].is_array())
                        content_str = m["content"].dump();
                }
                estimated_tokens += static_cast<int>(context_mgmt::estimate_token_count(content_str));
            }
            estimated_tokens += static_cast<int>(context_mgmt::estimate_token_count(system_prompt));

            double usage_fraction = static_cast<double>(estimated_tokens) / static_cast<double>(ctx_window);
            if (usage_fraction > g_sa_settings.condense_threshold && messages.size() > 4) {
                output_log::push(bottom_tab_t::output,
                    "[ai] Context at " + std::to_string(static_cast<int>(usage_fraction * 100)) +
                    "% — condensing conversation...");


                std::vector<std::pair<std::string, std::string>> old_msgs;
                for (size_t i = 0; i < messages.size() - 2; ++i) {
                    std::string role = messages[i].value("role", "user");
                    std::string content;
                    if (messages[i].contains("content")) {
                        if (messages[i]["content"].is_string())
                            content = messages[i]["content"].get<std::string>();
                        else if (messages[i]["content"].is_array())
                            content = messages[i]["content"].dump();
                    }
                    old_msgs.push_back({role, content});
                }
                std::string condense_prompt = context_mgmt::build_condensation_prompt(
                    old_msgs, user_message);

                std::string summary;
                try {
                    summary = g_sa_ai_client->chat_blocking(condense_prompt, {}, nullptr, nullptr);
                } catch (...) {
                    summary = "";
                }

                if (!summary.empty() && summary.substr(0, 6) != "Error:") {

                    json condensed = json::array();
                    condensed.push_back({
                        {"role", "user"},
                        {"content", "[Previous conversation summary]\n" + summary}
                    });
                    condensed.push_back({
                        {"role", "assistant"},
                        {"content", "I understand the context from the summary. I'll continue from here."}
                    });


                    size_t keep_from = messages.size() > 2 ? messages.size() - 2 : 0;
                    for (size_t i = keep_from; i < messages.size(); ++i)
                        condensed.push_back(messages[i]);

                    messages = condensed;

                    output_log::push(bottom_tab_t::output, "[ai] Conversation condensed to " +
                        std::to_string(messages.size()) + " messages");
                }
            }
        }

        if (turn > 0)
            post_update(ai_update_t::THINKING, "Processing tool results...");

        ai_generation_result_t gen;
        try {
            gen = g_sa_ai_client->generate_with_tools(messages, system_prompt, local_tools,
                [](const std::string& chunk) {
                    if (chunk.empty()) return;


                    if (chunk.size() > 7 && chunk[0] == '\x01' &&
                        chunk.compare(0, 7, "\x01THINK:") == 0) {
                        post_update(ai_update_t::THINKING, chunk.substr(7));
                    } else if (chunk[0] != '\x01') {
                        post_update(ai_update_t::CHUNK, chunk);
                    }
                });
        } catch (const std::exception& e) {
            diag::log_tagged_fmt("chat",
                "generate_with_tools_exception what=%.200s", e.what());
            output_log::push(bottom_tab_t::output, std::string("[ai] Exception: ") + e.what());
            post_update(ai_update_t::ERR, std::string("Exception: ") + e.what());
            return;
        }

        diag::log_tagged_fmt("chat",
            "generate_with_tools_done turn=%d is_error=%d in=%lld out=%lld text_len=%zu think_len=%zu tool_calls=%zu",
            turn, gen.is_error ? 1 : 0,
            static_cast<long long>(gen.input_tokens),
            static_cast<long long>(gen.output_tokens),
            gen.text.size(), gen.thinking.size(), gen.tool_calls.size());

        budget_used += gen.input_tokens + gen.output_tokens;

        if (s_cancel.load()) { post_update(ai_update_t::COMPLETE); return; }
        if (gen.is_error) {
            diag::log_tagged_fmt("chat",
                "generate_with_tools_error_returned text=%.200s", gen.text.c_str());
            post_update(ai_update_t::ERR, gen.text);
            return;
        }

        {
            std::string sid = get_chat_session_id_locked();
            if (!sid.empty()) {
                std::string active_model_id = g_sa_settings.get_active_model();
                std::string provider_id     = g_sa_settings.selected_provider_id();
                const aida::provider::model_info_t* mi =
                    aida::provider::catalog::get_model(provider_id, active_model_id);
                aida::session::usage_tokens_t usage;
                usage.input       = gen.input_tokens;
                usage.output      = gen.output_tokens;
                usage.cache_read  = gen.cache_read;
                usage.cache_write = gen.cache_write;

                std::string assistant_msg_id = get_chat_last_assistant_message_id_locked();
                if (mi != nullptr && !assistant_msg_id.empty()) {
                    (void)cost_calc::persist_step_finish(sid, assistant_msg_id, *mi, usage,
                                                        gen.tool_calls.empty() ? std::string("stop")
                                                                               : std::string("tool_use"));
                }

                add_chat_used_tokens_locked(gen.input_tokens + gen.output_tokens
                                             + gen.cache_read + gen.cache_write);

                if (mi != nullptr) {
                    int64_t ctx_limit = mi->limit.context > 0 ? mi->limit.context : 128000;
                    int64_t used      = get_chat_used_tokens_locked();
                    if (aida::compaction::should_trigger(sid, used, ctx_limit)) {
                        std::string comp_sid = sid;
                        work_queue::post([comp_sid]() {
                            aida::compaction::compaction_options_t opts;
                            aida::compaction::compaction_result_t out;
                            (void)aida::compaction::run(comp_sid, opts, out);
                        });
                    }
                }
            }
        }


        {
            uint64_t gate = standalone_license::inline_gate_check(
                standalone_license::gate_chat_post_response);
            if (standalone_license::verify_gate_token(
                    standalone_license::gate_chat_post_response, gate) < 0.5) {
                post_update(ai_update_t::ERR,
                    standalone_license::decode_status_string(
                        standalone_license::str_session_revoked));
                return;
            }
        }

        if (!gen.thinking.empty() && !gen.thinking_streamed)
            post_update(ai_update_t::THINKING, gen.thinking);


        if (gen.tool_calls.empty()) {


            if (gen.text.empty() && gen.thinking.empty())
                post_update(ai_update_t::CHUNK, "No response received from the model. Check your API key, model name, and network connection.");
            else if (gen.text.empty() && !gen.thinking.empty())
                post_update(ai_update_t::CHUNK, "(thinking only — no text output)");
            post_update(ai_update_t::COMPLETE);
            return;
        }


        json assistant_content = json::array();
        if (!gen.text.empty())
            assistant_content.push_back({{"type", "text"}, {"text", gen.text}});
        for (auto& tc : gen.tool_calls) {
            assistant_content.push_back({
                {"type", "tool_use"},
                {"id", tc.id},
                {"name", tc.name},
                {"input", tc.arguments}
            });
        }
        messages.push_back({{"role", "assistant"}, {"content", assistant_content}});


        json tool_result_content = json::array();
        for (auto& tc : gen.tool_calls) {
            if (s_cancel.load()) { post_update(ai_update_t::COMPLETE); return; }
            post_update(ai_update_t::THINKING, "Calling " + tc.name + "...");


            {
                uint64_t gate = standalone_license::inline_gate_check(
                    standalone_license::gate_chat_tool_exec);
                if (!standalone_license::verify_tool_runtime(
                        standalone_license::gate_chat_tool_exec, gate, tc.name)) {
                    tool_result_content.push_back(
                        standalone_ai_client_t::make_tool_result_block(tc.id, "Service unavailable.", true));
                    continue;
                }
            }

            if (!standalone_license::inline_proof_check_d()) {
                tool_result_content.push_back(
                    standalone_ai_client_t::make_tool_result_block(tc.id, "Error: Tool execution timed out.", true));
                continue;
            }

            if (!request_tool_approval(tc.name, tc.arguments)) {
                const std::string& deny_reason = tool_approval_last_deny_reason();
                const std::string  deny_text   = deny_reason.empty()
                    ? std::string("Tool execution denied by user.")
                    : deny_reason;
                tool_result_content.push_back(
                    standalone_ai_client_t::make_tool_result_block(tc.id, deny_text, true));
                continue;
            }

            std::string result = execute_tool(tc.name, tc.arguments);

            std::string repetition_msg;
            const auto rep_decision =
                note_tool_repetition(tc.name, tc.arguments, repetition_msg);
            if (rep_decision != tool_repetition_decision_t::none && !repetition_msg.empty()) {
                post_update(ai_update_t::THINKING, repetition_msg);
                output_log::push(bottom_tab_t::output,
                    "[ai] repetition detector: " + repetition_msg);
                if (rep_decision == tool_repetition_decision_t::force_ask &&
                    tc.name != "ask_followup_question") {
                    result += "\n\n[repetition guard] " + repetition_msg;
                }
            }

            bool is_err = (result.size() >= 6 && result.substr(0, 6) == "Error:");
            tool_result_content.push_back(
                standalone_ai_client_t::make_tool_result_block(tc.id, result, is_err));
        }


        messages.push_back({{"role", "user"}, {"content", tool_result_content}});
    }

    output_log::push(bottom_tab_t::output, "[ai] Reached max tool rounds (" + std::to_string(max_turns) + ")");
    post_update(ai_update_t::ERR, "Reached maximum tool-calling rounds (" + std::to_string(max_turns) + "). Stopping.");
}

void restore_workspace_state()
{
    if (!g_sa_settings.workspace.root_path.empty())
        file_browser::refresh(g_sa_settings.workspace.root_path);
    else
        file_browser::refresh();

    globals::ui::panel_left_w = g_sa_settings.workspace.left_width;
    globals::ui::panel_right_w = g_sa_settings.workspace.right_width;

    if (!g_sa_settings.workspace.open_tabs_json.empty()) {
        try {
            auto tabs = json::parse(g_sa_settings.workspace.open_tabs_json);
            if (tabs.is_array()) {
                for (const auto& item : tabs) {
                    if (!item.is_string())
                        continue;
                    const std::string path = item.get<std::string>();
                    std::ifstream ifs(path, std::ios::binary);
                    if (!ifs.is_open())
                        continue;
                    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
                    const auto filename = std::filesystem::path(path).filename().string();
                    file_tabs::open_or_focus(path, filename, content);
                }
                if (g_sa_settings.workspace.active_tab >= 0 &&
                    g_sa_settings.workspace.active_tab < static_cast<int>(file_tabs::tabs.size()))
                    file_tabs::active_tab = g_sa_settings.workspace.active_tab;
            }
        } catch (...) {
        }
    }

    if (!g_sa_settings.workspace.last_active_path.empty() &&
        g_sa_settings.workspace.active_view == "disasm") {
        loading_binary_overlay::begin_load(g_sa_settings.workspace.last_active_path,
            loading_binary_overlay::completion_action_t::none);
    }
}

void persist_workspace_state()
{
    g_sa_settings.workspace.root_path = file_browser::current_dir;
    g_sa_settings.workspace.left_width = globals::ui::panel_left_w;
    g_sa_settings.workspace.right_width = globals::ui::panel_right_w;
    g_sa_settings.workspace.active_tab = file_tabs::active_tab;

    json tabs = json::array();
    for (const auto& tab : file_tabs::tabs)
        tabs.push_back(tab.filepath);
    g_sa_settings.workspace.open_tabs_json = tabs.dump();

    if (code_editor::active && !code_editor::filepath.empty()) {
        g_sa_settings.workspace.last_active_path = code_editor::filepath;
        g_sa_settings.workspace.active_view = "editor";
    } else if (g_disasm.file.loaded && !g_disasm.file.path.empty()) {
        g_sa_settings.workspace.last_active_path = g_disasm.file.path;
        g_sa_settings.workspace.active_view = "disasm";
    }
}

}


namespace {


bool find_exe_code_section(HMODULE mod, std::uint64_t& out_base, std::uint32_t& out_size) {
    const auto* base_ptr = reinterpret_cast<const std::uint8_t*>(mod);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base_ptr);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base_ptr + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;

    const auto* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if ((section[i].Characteristics & IMAGE_SCN_CNT_CODE) != 0
            && section[i].Misc.VirtualSize > 0) {
            out_base = reinterpret_cast<std::uint64_t>(mod) + section[i].VirtualAddress;
            out_size = section[i].Misc.VirtualSize;
            return true;
        }
    }
    return false;
}


std::uint64_t hash_code_section(const void* data, std::size_t size) {
    const auto* ptr = static_cast<const std::uint8_t*>(data);
    std::uint64_t h1 = 0xFFFFFFFFULL;
    std::uint64_t h2 = 0x85EBCA6BULL;

    const std::size_t chunks = size / 8;
    const auto* ptr64 = reinterpret_cast<const std::uint64_t*>(ptr);
    for (std::size_t i = 0; i < chunks; ++i) {
        h1 = _mm_crc32_u64(h1, ptr64[i]);
        h2 = _mm_crc32_u64(h2, ptr64[i] ^ 0xA5A5A5A5A5A5A5A5ULL);
    }

    const std::size_t remaining = size % 8;
    const auto* tail = ptr + chunks * 8;
    for (std::size_t i = 0; i < remaining; ++i) {
        h1 = _mm_crc32_u8(static_cast<std::uint32_t>(h1), tail[i]);
        h2 = _mm_crc32_u8(static_cast<std::uint32_t>(h2), tail[i] ^ 0xA5u);
    }

    return (h1 & 0xFFFFFFFFULL) | ((h2 & 0xFFFFFFFFULL) << 32);
}


void register_standalone_protection() {
    if (!driver_bridge::using_kernel_driver()) {
        if (!driver_bridge::load_kernel_driver())
            return;
    }

    if (!standalone_license::is_valid()) {
        diag::log_tagged_fmt("init_chat",
            "register_standalone_protection_deferred auth_ok=0 arc_loaded=%d",
            standalone_license::is_arc_loaded() ? 1 : 0);
        return;
    }

    if (!driver_bridge::refresh_heartbeat())
        return;

    if (!driver_bridge::dynamic_ioctls_ready()) {
        diag::log_tagged_fmt("init_chat", "register_standalone_protection_deferred dynamic_ioctl_ready=0");
        return;
    }

    HMODULE exe_module = GetModuleHandleW(nullptr);
    if (!exe_module)
        return;

    std::uint64_t text_base = 0;
    std::uint32_t text_size = 0;
    if (!find_exe_code_section(exe_module, text_base, text_size) || text_size == 0)
        return;

    std::uint64_t text_hash = hash_code_section(
        reinterpret_cast<const void*>(text_base), text_size);
    if (text_hash == 0)
        return;

    const bool protected_ok = driver_bridge::register_self_dll_protection(
        reinterpret_cast<std::uint64_t>(exe_module),
        text_base,
        text_size,
        text_hash,
        2000
    );
    diag::log_tagged_fmt("init_chat",
        "register_standalone_protection_result ok=%d image=0x%016llX text=0x%016llX text_size=0x%08X hash=0x%016llX",
        protected_ok ? 1 : 0,
        static_cast<unsigned long long>(reinterpret_cast<std::uint64_t>(exe_module)),
        static_cast<unsigned long long>(text_base),
        text_size,
        static_cast<unsigned long long>(text_hash));
}

}


bool g_settings_open = false;


__declspec(noinline) static DWORD seh_settings_load(settings_sa_t& s, bool& out_ok)
{
    out_ok = false;
    __try {
        out_ok = s.load();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_standalone_license_initialize(settings_sa_t& s, bool& out_ok)
{
    out_ok = false;
    __try {
        out_ok = standalone_license::initialize(s);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_register_standalone_protection_call()
{
    __try {
        register_standalone_protection();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_restore_workspace_state()
{
    __try {
        restore_workspace_state();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return 0;
}

void init_standalone_chat()
{
    if (s_initialized) return;

    diag::log_tagged("init_chat", "settings_load_start");
    bool settings_loaded = false;
    DWORD seh_load = seh_settings_load(g_sa_settings, settings_loaded);
    if (seh_load != 0)
        diag::log_tagged_fmt("init_chat", "settings_load_seh code=0x%08X last_err=%lu", seh_load, GetLastError());
    diag::log_tagged_fmt("init_chat", "settings_load_done loaded=%d", settings_loaded ? 1 : 0);


    themes::active = std::clamp(g_sa_settings.active_theme_idx, 0, themes::count - 1);


    if (!g_sa_settings.custom_themes_json.empty()) {
        try {
            auto arr = nlohmann::json::parse(g_sa_settings.custom_themes_json);
            if (arr.is_array()) {
                custom_themes::list.clear();
                for (auto& jt : arr) {
                    CustomThemeData ct;
                    ct.name = jt.value("name", "Custom");
                    if (jt.contains("accent") && jt["accent"].is_array() && jt["accent"].size() >= 3) {
                        ct.accent[0] = jt["accent"][0].get<float>();
                        ct.accent[1] = jt["accent"][1].get<float>();
                        ct.accent[2] = jt["accent"][2].get<float>();
                    }
                    ct.bg_base       = jt.value("bg_base",       (uint32_t)ct.bg_base);
                    ct.panel_bg      = jt.value("panel_bg",      (uint32_t)ct.panel_bg);
                    ct.panel_header  = jt.value("panel_header",  (uint32_t)ct.panel_header);
                    ct.title_bar     = jt.value("title_bar",     (uint32_t)ct.title_bar);
                    ct.text_primary  = jt.value("text_primary",  (uint32_t)ct.text_primary);
                    ct.text_secondary= jt.value("text_secondary",(uint32_t)ct.text_secondary);
                    ct.text_dim      = jt.value("text_dim",      (uint32_t)ct.text_dim);
                    ct.acrylic_color = jt.value("acrylic_color", (DWORD)ct.acrylic_color);
                    ct.icon_index    = jt.value("icon_index",    ct.icon_index);
                    ct.icon_file_path= jt.value("icon_file_path", std::string{});
                    custom_themes::list.push_back(std::move(ct));
                }
            }
        } catch (...) {}
    }
    custom_themes::active_custom = g_sa_settings.active_custom_theme_idx;
    if (custom_themes::active_custom >= (int)custom_themes::list.size())
        custom_themes::active_custom = -1;


    editor_config::tab_size               = g_sa_settings.editor_tab_size;
    editor_config::font_size              = g_sa_settings.editor_font_size;
    editor_config::auto_complete          = g_sa_settings.editor_auto_complete;
    editor_config::show_line_numbers      = g_sa_settings.editor_line_numbers;
    editor_config::highlight_current_line = g_sa_settings.editor_highlight_line;
    editor_config::word_wrap              = g_sa_settings.editor_word_wrap;
    editor_config::minimap                = g_sa_settings.editor_minimap;
    editor_config::bracket_match          = g_sa_settings.editor_bracket_match;

    themes::changed = true;


    diag::log_tagged("init_chat", "license_initialize_start");
    bool license_ok = false;
    DWORD seh_lic = seh_standalone_license_initialize(g_sa_settings, license_ok);
    if (seh_lic != 0)
        diag::log_tagged_fmt("init_chat", "license_initialize_seh code=0x%08X last_err=%lu", seh_lic, GetLastError());
    license::validated = license_ok;
    license::saved_key = g_sa_settings.license_key;
    strncpy_s(license::key_buf, sizeof(license::key_buf),
              g_sa_settings.license_key.c_str(), _TRUNCATE);
    if (!license::validated && !standalone_license::last_error().empty())
        license::error_msg = standalone_license::last_error();
    license::check_failed = !license::validated && !license::error_msg.empty();
    diag::log_tagged_fmt("init_chat", "license_initialize_done validated=%d", license::validated ? 1 : 0);

    diag::log_tagged("init_chat", "ai_client_create_start");
    g_sa_ai_client = std::make_unique<standalone_ai_client_t>(g_sa_settings);
    diag::log_tagged("init_chat", "ai_client_create_done");

    diag::log_tagged("init_chat", "auth_store_load_start");
    (void)aida::auth::store::load();
    diag::log_tagged("init_chat", "auth_store_load_done");

    diag::log_tagged("init_chat", "session_store_init_start");
    (void)aida::session::initialize();
    diag::log_tagged("init_chat", "session_store_init_done");

    diag::log_tagged("init_chat", "agent_registry_init_start");
    aida::agent::initialize();
    (void)aida::agent::load_custom_from_disk();
    if (!g_sa_settings.default_agent_name.empty() &&
        aida::agent::get(g_sa_settings.default_agent_name) != nullptr) {
        aida::agent::set_default_agent_name(g_sa_settings.default_agent_name);
        aida::agent::set_active_agent(g_sa_settings.default_agent_name);
    } else {
        aida::agent::set_active_agent(aida::agent::default_agent_name());
    }
    diag::log_tagged("init_chat", "agent_registry_init_done");

    diag::log_tagged("init_chat", "command_registry_init_start");
    (void)aida::commands::initialize();
    diag::log_tagged("init_chat", "command_registry_init_done");

    diag::log_tagged("init_chat", "views_initialize_start");
    aida::auth_view::initialize();
    aida::provider_view::initialize();
    aida::agent_picker::initialize();
    aida::agent_manager::initialize();
    aida::skill_manager::initialize();
    aida::binary_map_view::initialize();
    aida::command_palette::initialize();
    aida::settings_overlay::initialize();
    diag::log_tagged("init_chat", "views_initialize_done");

    diag::log_tagged("init_chat", "mcp_register_tools_deferred_until_authorized_ide");
    diag::log_tagged("init_chat", "mcp_server_start_deferred_until_authorized_ide");

    diag::log_tagged_fmt("init_chat", "mcp_client_add_servers count=%zu", g_sa_settings.mcp_client_servers.size());
    for (const auto& srv : g_sa_settings.mcp_client_servers) {
        mcp_client::server_config_t cfg;
        cfg.name         = srv.name;
        cfg.url          = srv.url;
        cfg.api_key      = srv.api_key;
        cfg.enabled      = srv.enabled;
        cfg.auto_connect = srv.auto_connect;
        if (srv.transport == "stdio") {
            cfg.transport = mcp_client::transport_type_t::stdio;
            cfg.command   = srv.command;

            if (!srv.args.empty()) {
                std::istringstream iss(srv.args);
                std::string arg;
                while (iss >> arg)
                    cfg.args.push_back(arg);
            }
        } else {
            cfg.transport = mcp_client::transport_type_t::http_sse;
        }
        s_mcp_client_mgr.add_server(cfg);
    }
    diag::log_tagged("init_chat", "mcp_client_connect_all_start");
    diag::log_tagged("init_chat", "mcp_client_connect_all_deferred_until_authorized_ide");

    diag::log_tagged("init_chat", "marketplace_load_installed_start");
    mcp_marketplace::load_installed(g_sa_settings.marketplace_installed_json);
    diag::log_tagged("init_chat", "marketplace_autoconnect_deferred_until_authorized_ide");
    diag::log_tagged("init_chat", "marketplace_load_installed_done");

    diag::log_tagged("init_chat", "driver_bridge_initialize_start");
    driver_bridge::initialize();
    diag::log_tagged("init_chat", "driver_bridge_initialize_done");

    diag::log_tagged("init_chat", "register_standalone_protection_start");
    DWORD seh_rsp = seh_register_standalone_protection_call();
    if (seh_rsp != 0)
        diag::log_tagged_fmt("init_chat", "register_standalone_protection_seh code=0x%08X last_err=%lu", seh_rsp, GetLastError());
    diag::log_tagged("init_chat", "register_standalone_protection_done");

    diag::log_tagged("init_chat", "restore_workspace_state_start");
    DWORD seh_rws = seh_restore_workspace_state();
    if (seh_rws != 0)
        diag::log_tagged_fmt("init_chat", "restore_workspace_state_seh code=0x%08X last_err=%lu", seh_rws, GetLastError());
    diag::log_tagged("init_chat", "restore_workspace_state_done");

    output_log::push(bottom_tab_t::output, "[init] AiDA Standalone initialized");
    output_log::push(bottom_tab_t::output, "[init] License: " + std::string(license::validated ? "valid" : "not validated"));
    if (s_server_started)
        output_log::push(bottom_tab_t::mcp_log, "[mcp-server] Started on port " + std::to_string(g_sa_settings.mcp_port));
    output_log::push(bottom_tab_t::driver_log, "[driver] Bridge initialized");

    s_initialized = true;
}

void start_authorized_mcp_services()
{
    if (!s_initialized)
        return;

    if (!anti_tamper::mcp_posture::is_current_posture_trusted())
    {
        mcp_standalone::set_ide_lifecycle_ready(false);
        static auto s_last_posture_block_log = std::chrono::steady_clock::time_point{};
        auto now = std::chrono::steady_clock::now();
        if (s_last_posture_block_log == std::chrono::steady_clock::time_point{} ||
            std::chrono::duration_cast<std::chrono::seconds>(now - s_last_posture_block_log).count() >= 2)
        {
            diag::log_tagged_fmt("init_chat",
                "authorized_mcp_services_blocked_mcp_posture summary_hash=0x%016llX",
                static_cast<unsigned long long>(anti_tamper::mcp_posture::cached_summary_hash()));
            s_last_posture_block_log = now;
        }
        return;
    }

    std::string missing_exports;
    const bool ide_ready = s_ide_ready_for_mcp_services.load(std::memory_order_acquire);
    const bool valid = license::validated && standalone_license::is_valid();
    const bool arc_loaded = standalone_license::is_arc_loaded();
    const bool exports_ok = valid && arc_loaded && standalone_license::validate_arc_required_exports(missing_exports);
    if (!ide_ready || !valid || !arc_loaded || !exports_ok)
    {
        mcp_standalone::set_ide_lifecycle_ready(false);
        static auto s_last_block_log = std::chrono::steady_clock::time_point{};
        auto now = std::chrono::steady_clock::now();
        if (s_last_block_log == std::chrono::steady_clock::time_point{} ||
            std::chrono::duration_cast<std::chrono::seconds>(now - s_last_block_log).count() >= 2)
        {
            diag::log_tagged_fmt("init_chat",
                "authorized_mcp_services_blocked ide=%d validated=%d valid=%d arc=%d exports=%d missing='%.160s'",
                ide_ready ? 1 : 0,
                license::validated ? 1 : 0,
                standalone_license::is_valid() ? 1 : 0,
                standalone_license::is_arc_loaded() ? 1 : 0,
                exports_ok ? 1 : 0,
                missing_exports.c_str());
            s_last_block_log = now;
        }
        return;
    }

    mcp_standalone::set_ide_lifecycle_ready(true);

    if (!s_mcp_tools_registered)
    {
        diag::log_tagged("init_chat", "authorized_mcp_register_tools_start");
        mcp_standalone::register_standalone_tools(s_mcp_server);
        s_mcp_tools_registered = true;
        diag::log_tagged("init_chat", "authorized_mcp_register_tools_done");
    }

    if (g_sa_settings.mcp_enabled && !s_server_started)
    {
        static auto s_last_start_attempt = std::chrono::steady_clock::time_point{};
        auto now = std::chrono::steady_clock::now();
        if (s_last_start_attempt != std::chrono::steady_clock::time_point{} &&
            std::chrono::duration_cast<std::chrono::seconds>(now - s_last_start_attempt).count() < 2)
        {
            return;
        }
        s_last_start_attempt = now;
        diag::log_tagged_fmt("init_chat",
            "authorized_mcp_server_start port=%d ide=%d validated=%d valid=%d arc=%d exports=%d",
            g_sa_settings.mcp_port,
            ide_ready ? 1 : 0,
            license::validated ? 1 : 0,
            standalone_license::is_valid() ? 1 : 0,
            standalone_license::is_arc_loaded() ? 1 : 0,
            exports_ok ? 1 : 0);
        if (s_mcp_server.start(g_sa_settings.mcp_port))
        {
            s_server_started = true;
            bool posted = critical_work_queue::post([] {
                try {
                    diag::log_tagged("init_chat", "authorized_mcp_write_client_configs_start");
                    s_mcp_server.write_client_configs();
                    diag::log_tagged("init_chat", "authorized_mcp_write_client_configs_done");
                } catch (const std::exception& e) {
                    diag::log_tagged_fmt("init_chat", "authorized_mcp_write_client_configs_cpp_exception what=%s", e.what());
                } catch (...) {
                    diag::log_tagged("init_chat", "authorized_mcp_write_client_configs_cpp_exception what=<unknown>");
                }
            });
            if (!posted)
                diag::log_tagged("init_chat", "authorized_mcp_write_client_configs_critical_post_failed");
        }
        diag::log_tagged_fmt("init_chat", "authorized_mcp_server_start_done started=%d", s_server_started ? 1 : 0);
    }

    if (!s_mcp_clients_connected)
    {
        diag::log_tagged("init_chat", "authorized_mcp_client_connect_all_start");
        s_mcp_client_mgr.connect_all();
        s_mcp_clients_connected = true;
        diag::log_tagged("init_chat", "authorized_mcp_client_connect_all_done");

        auto installed = mcp_marketplace::get_installed();
        for (auto& srv : installed)
        {
            if (srv.enabled && srv.auto_connect)
                mcp_marketplace::activate_server(srv);
        }
        diag::log_tagged_fmt("init_chat", "authorized_marketplace_autoconnect_done count=%zu", installed.size());
    }
}

void mark_ide_ready_for_mcp_services()
{
    s_ide_ready_for_mcp_services.store(true, std::memory_order_release);
}

void shutdown_standalone_chat()
{
    diag::log_tagged("chat", "shutdown_standalone_chat enter");
    s_cancel = true;
    {
        std::lock_guard<std::mutex> lk(s_ai_thread_mtx);
        s_cancel = true;
        if (g_sa_ai_client) g_sa_ai_client->cancel();
        if (!s_ai_task_done.load()) {
            std::unique_lock<std::mutex> lk2(s_ai_task_done_mtx);
            s_ai_task_done_cv.wait(lk2, []() { return s_ai_task_done.load(); });
        }
    }
    s_mcp_server.stop();
    s_server_started = false;
    mcp_standalone::set_ide_lifecycle_ready(false);
    s_ide_ready_for_mcp_services.store(false, std::memory_order_release);


    if (s_mcp_clients_connected) {
        s_mcp_client_mgr.disconnect_all();
        s_mcp_clients_connected = false;
    }


    g_sa_settings.marketplace_installed_json = mcp_marketplace::save_installed();
    mcp_marketplace::shutdown();

    aida::settings_overlay::shutdown();
    aida::command_palette::shutdown();
    aida::binary_map_view::shutdown();
    aida::skill_manager::shutdown();
    aida::agent_manager::shutdown();
    aida::agent_picker::shutdown();
    aida::provider_view::shutdown();
    aida::auth_view::shutdown();

    (void)aida::session::shutdown();
    aida::events::shutdown();
    critical_work_queue::shutdown();
    work_queue::shutdown();

    persist_workspace_state();
    g_sa_settings.save();
    standalone_license::shutdown();
    g_sa_ai_client.reset();


    if (driver_bridge::using_kernel_driver())
        driver_bridge::unregister_dll_protection();

    s_initialized = false;
    diag::log_tagged("chat", "shutdown_standalone_chat done");
}


void tick_ai_chat()
{
    if (!s_initialized) return;
    if (g_chat_messages.empty()) return;

    auto& last = g_chat_messages.back();
    if (!last.is_user || s_ai_running.load()) return;


    std::string user_text = last.text;


    if (!user_text.empty() && user_text[0] == '/') {
        size_t name_end = 1;
        while (name_end < user_text.size() &&
               user_text[name_end] != ' ' &&
               user_text[name_end] != '\t' &&
               user_text[name_end] != '\n') {
            ++name_end;
        }
        const std::string cmd_name = user_text.substr(1, name_end - 1);
        std::vector<std::string> cmd_args;
        if (name_end < user_text.size()) {
            std::string rest = user_text.substr(name_end);
            size_t s = 0;
            while (s < rest.size() && (rest[s] == ' ' || rest[s] == '\t')) ++s;
            while (s < rest.size()) {
                if (rest[s] == '"' || rest[s] == '\'') {
                    const char quote = rest[s];
                    ++s;
                    std::string tok;
                    while (s < rest.size() && rest[s] != quote) {
                        if (rest[s] == '\\' && s + 1 < rest.size() &&
                            (rest[s + 1] == quote || rest[s + 1] == '\\')) {
                            tok.push_back(rest[s + 1]);
                            s += 2;
                        } else {
                            tok.push_back(rest[s]);
                            ++s;
                        }
                    }
                    if (s < rest.size() && rest[s] == quote) ++s;
                    cmd_args.push_back(std::move(tok));
                } else {
                    size_t e = s;
                    while (e < rest.size() && rest[e] != ' ' && rest[e] != '\t') ++e;
                    cmd_args.push_back(rest.substr(s, e - s));
                    s = e;
                }
                while (s < rest.size() && (rest[s] == ' ' || rest[s] == '\t')) ++s;
            }
        }

        aida::commands::command_t cmd;
        const bool found = aida::commands::find(cmd_name, cmd);
        if (found) {
            std::string resolved;
            const bool ok = aida::commands::execute(cmd_name, cmd_args, resolved);
            if (!ok) {
                ChatMessage err;
                err.is_user = false;
                err.has_thinking = false;
                err.streaming = false;
                err.text = std::string("[/")+ cmd_name + "] " + aida::commands::last_error();
                g_chat_messages.push_back(err);
                g_chat_scroll_to_bottom = true;
                return;
            }

            const bool is_programmatic =
                (cmd.source == aida::commands::command_source_t::builtin && cmd.template_text.empty()) ||
                (cmd.source == aida::commands::command_source_t::agent);
            if (is_programmatic) {
                ChatMessage out_msg;
                out_msg.is_user = false;
                out_msg.has_thinking = false;
                out_msg.streaming = false;
                out_msg.text = resolved.empty()
                    ? (std::string("[/") + cmd_name + "] done")
                    : resolved;
                g_chat_messages.push_back(out_msg);
                g_chat_scroll_to_bottom = true;
                return;
            }

            user_text = resolved;
            last.text = resolved;
        }
    }


    if (!g_sa_ai_client || !g_sa_ai_client->is_available()) {
        ChatMessage ai;
        ai.is_user       = false;
        ai.has_thinking   = false;
        ai.streaming      = false;
        ai.text           = "AI not configured. Click \"Settings\" in the chat header to set your API key and model.";
        g_chat_messages.push_back(ai);
        g_chat_scroll_to_bottom = true;
        return;
    }


    g_ai_thinking_active = false;


    ChatMessage ai;
    ai.is_user       = false;
    ai.has_thinking   = true;
    ai.streaming      = true;
    ai.thinking_text  = "";
    ai.text           = "";
    {
        const std::string sel_provider = g_sa_settings.selected_provider_id();
        const std::string sel_model    = g_sa_settings.selected_model_id();
        std::string m_disp = sel_model;
        if (!sel_provider.empty() && !sel_model.empty()) {
            const auto* m = aida::provider::catalog::get_model(sel_provider, sel_model);
            if (m != nullptr && !m->name.empty())
                m_disp = m->name;
        }
        if (m_disp.empty()) {
            auto* prof = g_sa_settings.get_active_profile();
            if (prof) m_disp = prof->model;
        }
        ai.model_id = m_disp;
        diag::log_tagged_fmt("chat",
            "new_assistant_message provider=%.40s model=%.80s",
            sel_provider.c_str(), m_disp.c_str());
    }
    g_chat_messages.push_back(ai);
    g_chat_scroll_to_bottom = true;


    std::vector<std::pair<std::string, std::string>> history;
    for (int i = 0; i < (int)g_chat_messages.size() - 2; ++i) {
        auto& m = g_chat_messages[i];
        if (!m.text.empty())
            history.emplace_back(m.is_user ? "User" : "Assistant", m.text);
    }

    {
        std::string sid_check = get_chat_session_id_locked();
        if (sid_check.empty() && conversations::current_id.empty()) {
            aida::session::session_info_t info;
            if (aida::session::create(info, std::string{}, std::string{}, std::string{})) {
                conversations::current_id = info.id;
                chat_bind_session(info.id);
            }
        } else if (sid_check.empty() && !conversations::current_id.empty()) {
            chat_bind_session(conversations::current_id);
        } else if (!sid_check.empty() && conversations::current_id.empty()) {
            conversations::current_id = sid_check;
        }
    }

    {
        std::string sid = get_chat_session_id_locked();
        if (!sid.empty()) {
            int user_count = 0;
            for (const auto& m : g_chat_messages) {
                if (m.is_user) ++user_count;
            }
            if (user_count == 1) {
                std::string first_user_text = user_text;
                std::string provider_id     = g_sa_settings.selected_provider_id();
                work_queue::post([sid, first_user_text, provider_id]() {
                    (void)aida::compaction::maybe_auto_title(sid, first_user_text, provider_id);
                });
            }
        }
    }


    {
        std::lock_guard<std::mutex> lk(s_ai_thread_mtx);
        if (s_ai_running.load()) {
            s_cancel = true;
            if (g_sa_ai_client) g_sa_ai_client->cancel();
        }
        if (!s_ai_task_done.load()) {
            std::unique_lock<std::mutex> lk2(s_ai_task_done_mtx);
            s_ai_task_done_cv.wait(lk2, []() { return s_ai_task_done.load(); });
        }
        s_cancel      = false;
        s_ai_running  = true;
        s_ai_task_done.store(false);
        work_queue::post([user_text = std::move(user_text), history = std::move(history)]() mutable {
            run_agentic(std::move(user_text), std::move(history));
            s_ai_task_done.store(true);
            s_ai_task_done_cv.notify_all();
        });
    }
}


void poll_ai_chat()
{
    if (!s_initialized) return;

    if (license::validated && !standalone_license::is_valid()) {
        const bool runtime_locked = anti_tamper::state::get().violation_latched.load(std::memory_order_acquire);
        if (license::preserve_valid_state(runtime_locked, test_all_features::is_running())) {
            license::checking = false;
            license::check_failed = false;
            license::error_msg.clear();
            diag::log_tagged_fmt("license",
                "DIAG_DIALOG_TRIGGER_SUPPRESSED source=poll_ai_chat tid=%lu full_test=1 arc=%d",
                GetCurrentThreadId(),
                standalone_license::is_arc_loaded() ? 1 : 0);
        } else {
            license::validated = false;
            license::check_failed = true;
            license::error_msg = runtime_locked
                ? std::string("Runtime integrity check failed. Restart AiDAStandalone.exe.")
                : standalone_license::last_error();
            diag::log_tagged_fmt("license",
                "DIAG_DIALOG_TRIGGER source=poll_ai_chat tid=%lu runtime_locked=%d err=%.200s",
                GetCurrentThreadId(), runtime_locked ? 1 : 0, license::error_msg.c_str());
            mcp_standalone::set_ide_lifecycle_ready(false);
            s_ide_ready_for_mcp_services.store(false, std::memory_order_release);
            if (s_server_started) {
                diag::log_tagged("init_chat", "authorized_mcp_server_stop_auth_lost");
                s_mcp_server.stop();
                s_server_started = false;
            }
            if (s_mcp_clients_connected) {
                diag::log_tagged("init_chat", "authorized_mcp_client_disconnect_auth_lost");
                s_mcp_client_mgr.disconnect_all();
                s_mcp_clients_connected = false;
            }
        }
    }

    {
        std::string lifecycle_reason;
        if ((s_server_started || s_mcp_clients_connected) &&
            !mcp_standalone::lifecycle_authorized(&lifecycle_reason))
        {
            diag::log_tagged_fmt("init_chat",
                "authorized_mcp_services_stop_unauthorized reason='%.160s'",
                lifecycle_reason.c_str());
            mcp_standalone::set_ide_lifecycle_ready(false);
            s_ide_ready_for_mcp_services.store(false, std::memory_order_release);
            if (s_server_started) {
                s_mcp_server.stop();
                s_server_started = false;
            }
            if (s_mcp_clients_connected) {
                s_mcp_client_mgr.disconnect_all();
                s_mcp_clients_connected = false;
            }
        }
    }


    {
        static auto s_last_poll = std::chrono::steady_clock::now();
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - s_last_poll).count() >= 5) {
            s_mcp_client_mgr.poll();
            s_last_poll = now;
        }
    }

    std::deque<ai_update_t> local;
    {
        std::lock_guard<std::mutex> lk(s_update_mtx);
        std::swap(local, s_updates);
    }

    for (auto& u : local) {
        if (g_chat_messages.empty()) continue;
        auto& last = g_chat_messages.back();
        if (last.is_user) continue;

        switch (u.type) {
        case ai_update_t::THINKING:
            if (!u.text.empty()) {
                if (!last.thinking_text.empty())
                    last.thinking_text += "\n";
                last.thinking_text += u.text;
            }
            break;

        case ai_update_t::CHUNK:
            if (!g_ai_thinking_active) g_ai_thinking_active = true;
            last.text += u.text;
            g_chat_scroll_to_bottom = true;
            break;

        case ai_update_t::COMPLETE:
            last.streaming = false;
            g_ai_thinking_active = true;
            s_ai_running         = false;
            g_chat_scroll_to_bottom = true;
            break;

        case ai_update_t::ERR:
            g_ai_thinking_active = true;
            if (!u.text.empty()) last.text = u.text;
            last.streaming       = false;
            s_ai_running         = false;
            g_chat_scroll_to_bottom = true;
            break;
        }
    }
}


bool is_ai_busy()
{
    return s_ai_running.load();
}

void chat_request_cancel()
{
    if (!s_ai_running.load()) return;
    s_cancel = true;
    if (g_sa_ai_client) g_sa_ai_client->cancel();
}


std::atomic<bool>* chat_cancel_flag()
{
    return &s_cancel;
}


void chat_bind_session(const std::string& session_id)
{
    diag::log_tagged_fmt("chat", "chat_bind_session id='%s'", session_id.c_str());
    set_chat_session_id_locked(session_id);
}


std::string chat_active_session()
{
    return get_chat_session_id_locked();
}


void chat_record_assistant_message_id(const std::string& message_id)
{
    set_chat_last_assistant_message_id_locked(message_id);
}


std::string start_new_conversation()
{
    diag::log_tagged("chat", "start_new_conversation enter");
    aida::session::session_info_t info;
    std::string new_id;
    if (aida::session::create(info, std::string{}, std::string{}, std::string{}))
        new_id = info.id;

    conversations::current_id = new_id;
    chat_bind_session(new_id);
    g_chat_messages.clear();
    g_chat_buf[0] = '\0';
    g_chat_scroll_to_bottom = true;

    workflow_tools::get_repetition_detector().reset();

    diag::log_tagged_fmt("chat", "start_new_conversation done new_id='%s'", new_id.c_str());
    return new_id;
}


void render_tool_approval_dialog()
{
    bool show = false;
    std::string name, args_preview;
    {
        std::lock_guard<std::mutex> lk(s_tool_approval.mtx);
        if (s_tool_approval.pending && !s_tool_approval.answered) {
            show = true;
            name = s_tool_approval.tool_name;
            args_preview = s_tool_approval.tool_args_preview;
        }
    }
    if (!show) return;

    ImGui::OpenPopup("##tool_approval");

    float ww = globals::ui::window_w;
    float wh = globals::ui::window_h;
    float pw = 440.f, ph = 280.f;
    ImGui::SetNextWindowPos(ImVec2((ww - pw) * 0.5f, (wh - ph) * 0.5f), ImGuiCond_Appearing);
    ImGui::SetNextWindowSize(ImVec2(pw, ph), ImGuiCond_Always);

    ImGui::PushStyleColor(ImGuiCol_PopupBg, aida::ui::resolved().bg_elevated);
    ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::resolved().border_strong);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16, 12));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8.f);

    if (ImGui::BeginPopupModal("##tool_approval", nullptr,
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove)) {

        float ax = globals::ui::accent.x;
        float ay = globals::ui::accent.y;
        float az = globals::ui::accent.z;

        ImGui::PushFont(nullptr);
        ImGui::TextColored(ImVec4(ax, ay, az, 1.f), "Tool Approval Required");
        ImGui::PopFont();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::Text("The AI wants to execute:");
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::resolved().warning), "  %s", name.c_str());
        ImGui::Spacing();

        if (!args_preview.empty()) {
            ImGui::Text("Arguments:");
            ImGui::PushStyleColor(ImGuiCol_ChildBg, aida::ui::with_alpha(aida::ui::resolved().bg_base, 0.78f));
            ImGui::BeginChild("##tool_args", ImVec2(-1, 100.f), ImGuiChildFlags_Borders);
            ImGui::TextWrapped("%s", args_preview.c_str());
            ImGui::EndChild();
            ImGui::PopStyleColor();
        }

        ImGui::Spacing();
        ImGui::Spacing();

        float btn_w = 100.f;
        float total = btn_w * 2 + 12.f;
        ImGui::SetCursorPosX((pw - total) * 0.5f);

        if (aida::ui::components::button("Allow",
            aida::ui::components::button_kind_t::primary,
            aida::ui::components::size_t_::md,
            ImVec2(btn_w, 28.f))) {
            std::lock_guard<std::mutex> lk(s_tool_approval.mtx);
            s_tool_approval.approved = true;
            s_tool_approval.answered = true;
            s_tool_approval.cv.notify_one();
            ImGui::CloseCurrentPopup();
        }

        ImGui::SameLine(0, 12.f);

        if (aida::ui::components::button("Deny",
            aida::ui::components::button_kind_t::destructive,
            aida::ui::components::size_t_::md,
            ImVec2(btn_w, 28.f))) {
            std::lock_guard<std::mutex> lk(s_tool_approval.mtx);
            s_tool_approval.approved = false;
            s_tool_approval.answered = true;
            s_tool_approval.cv.notify_one();
            ImGui::CloseCurrentPopup();
        }

        ImGui::EndPopup();
    }
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);
}


void render_settings_inline(float panel_w, float panel_h)
{
    aida::settings_overlay::render_inline(panel_w, panel_h);
}


mcp_client::manager_t& get_mcp_client_manager()
{
    return s_mcp_client_mgr;
}

mcp_standalone::server_t& get_local_mcp_server()
{
    return s_mcp_server;
}

std::vector<mcp_standalone::tool_def_t> snapshot_local_tools()
{
    std::vector<mcp_standalone::tool_def_t> out;
    const auto& tools = s_mcp_server.get_tools();
    out.reserve(tools.size());
    for (const auto& t : tools) out.push_back(t);
    return out;
}

std::string execute_local_tool(const std::string& name, const nlohmann::json& arguments)
{
    return execute_tool(name, arguments);
}

file_context::tracker_t& get_file_tracker()
{
    return s_file_tracker;
}

void do_process_attach(unsigned long pid)
{
    diag::log_tagged_fmt("chat", "do_process_attach pid=%lu driver_loaded=%d",
        pid, static_cast<int>(driver_bridge::is_loaded()));
    const uint32_t target_pid = static_cast<uint32_t>(pid);
    const uint32_t previous_pid = driver_bridge::attached_pid();
    if (previous_pid != 0 && previous_pid != target_pid)
        stealth_engine::disable_for_detach(previous_pid, "chat.process_attach.replace");
    if (driver_bridge::attach(pid)) {
        const bool stealth_ok = stealth_engine::ensure_default_enabled(target_pid, "chat.process_attach");
        output_log::push(bottom_tab_t::driver_log, "[driver] Attached to PID " + std::to_string(pid));
        diag::log_tagged_fmt("chat", "do_process_attach SUCCESS pid=%lu stealth_ok=%d", pid, stealth_ok ? 1 : 0);
    } else {
        if (previous_pid != 0 && driver_bridge::attached_pid() == previous_pid)
            (void)stealth_engine::ensure_default_enabled(previous_pid, "chat.process_attach.restore_failed_switch");
        output_log::push(bottom_tab_t::driver_log, "[driver] Failed to attach to PID " + std::to_string(pid) +
                         ": " + driver_bridge::last_error());
        diag::log_tagged_fmt("chat", "do_process_attach FAILED pid=%lu error='%s'",
            pid, driver_bridge::last_error().c_str());
    }
}

void do_process_detach()
{
    diag::log_tagged_fmt("chat", "do_process_detach pid=%u",
        driver_bridge::attached_pid());
    stealth_engine::disable_for_detach(driver_bridge::attached_pid(), "chat.process_detach");
    driver_bridge::detach();
    output_log::push(bottom_tab_t::driver_log, "[driver] Detached from process");
    diag::log_tagged("chat", "do_process_detach done");
}

bool is_process_attached()
{
    return driver_bridge::attached_pid() != 0;
}

std::string get_attached_process_name()
{
    return driver_bridge::status();
}

unsigned long get_attached_pid()
{
    return driver_bridge::attached_pid();
}

namespace {

ImU32 hex_to_imu32_or_default(const std::string& hex, ImU32 fallback)
{
    if (hex.size() < 7 || hex[0] != '#') return fallback;
    auto h = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };
    int r1 = h(hex[1]), r2 = h(hex[2]), g1 = h(hex[3]), g2 = h(hex[4]), b1 = h(hex[5]), b2 = h(hex[6]);
    if (r1 < 0 || r2 < 0 || g1 < 0 || g2 < 0 || b1 < 0 || b2 < 0) return fallback;
    return IM_COL32(r1 * 16 + r2, g1 * 16 + g2, b1 * 16 + b2, 235);
}

void plan_build_pill_meta(std::string& label, std::string& glyph, ImU32& bg, ImU32& fg)
{
    const std::string active = aida::agent::active_agent_name();
    if (active == "plan") {
        glyph = "PLAN";
        label = "PLAN";
        bg = aida::ui::with_alpha(aida::ui::resolved().info, 0.9f);
        fg = aida::ui::is_dark() ? IM_COL32(245, 246, 252, 245) : IM_COL32(20, 22, 30, 245);
        return;
    }
    if (active == "build") {
        glyph = "BUILD";
        label = "BUILD";
        bg = aida::ui::with_alpha(aida::ui::resolved().success, 0.9f);
        fg = aida::ui::is_dark() ? IM_COL32(245, 246, 252, 245) : IM_COL32(20, 22, 30, 245);
        return;
    }
    glyph = active.empty() ? std::string("?") : active.substr(0, 1);
    label = active.empty() ? std::string("agent") : active;
    const aida::agent::agent_info_t* info = aida::agent::get(active);
    ImU32 col = info != nullptr
        ? hex_to_imu32_or_default(info->color, aida::ui::with_alpha(aida::ui::resolved().text_secondary, 0.9f))
        : aida::ui::with_alpha(aida::ui::resolved().text_secondary, 0.9f);
    bg = col;
    int rr = (col >> 0) & 0xFF;
    int gg = (col >> 8) & 0xFF;
    int bb = (col >> 16) & 0xFF;
    float lum = 0.299f * (rr / 255.f) + 0.587f * (gg / 255.f) + 0.114f * (bb / 255.f);
    fg = lum < 0.5f ? IM_COL32(245, 246, 252, 245) : IM_COL32(20, 22, 30, 245);
}

}

void chat_handle_agent_shortcuts()
{
    bool ctrl = ImGui::GetIO().KeyCtrl;
    bool shift = ImGui::GetIO().KeyShift;
    if (!(ctrl && shift)) return;

    if (ImGui::IsKeyPressed(ImGuiKey_A, false)) {
        if (aida::agent_picker::is_open())
            aida::agent_picker::close();
        else
            aida::agent_picker::open();
        return;
    }
    if (ImGui::IsKeyPressed(ImGuiKey_M, false)) {
        std::string current = aida::agent::active_agent_name();
        std::string target = (current == "plan") ? std::string("build") : std::string("plan");
        if (aida::agent::set_active_agent(target)) {
            aida::events::publish(aida::events::event_agent_changed,
                aida::events::agent_changed_t{ chat_active_session(), current, target });
        }
    }
}

namespace {
struct agent_pill_anim_t { float hover = 0.f; };
inline agent_pill_anim_t& agent_pill_anim()
{
    static agent_pill_anim_t s;
    return s;
}
}

float chat_agent_pill_width()
{
    std::string label, glyph;
    ImU32 bg, fg;
    plan_build_pill_meta(label, glyph, bg, fg);
    ImVec2 ts = ImGui::CalcTextSize(label.c_str());
    const float pad_x = 12.f;
    const float dot_r = 4.f;
    const float dot_block = dot_r * 2.f + 6.f;
    const float gap = 6.f;
    const float chev_w = 10.f;
    return pad_x + dot_block + ts.x + gap + chev_w + pad_x;
}

void chat_render_agent_pill(float anchor_x, float anchor_y, float alpha)
{
    if (alpha <= 0.001f) return;

    std::string label, glyph;
    ImU32 bg, fg;
    plan_build_pill_meta(label, glyph, bg, fg);

    const auto& th = aida::ui::resolved();
    auto& anim = agent_pill_anim();
    float dt = ImGui::GetIO().DeltaTime;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 ts = ImGui::CalcTextSize(label.c_str());
    const float pill_h = 22.f;
    const float pad_x = 12.f;
    const float dot_r = 4.f;
    const float dot_block = dot_r * 2.f + 6.f;
    const float gap = 6.f;
    const float chev_w = 10.f;
    const float pill_w = pad_x + dot_block + ts.x + gap + chev_w + pad_x;

    ImVec2 pmin(anchor_x, anchor_y);
    ImVec2 pmax(anchor_x + pill_w, anchor_y + pill_h);

    ImVec2 wp = ImGui::GetWindowPos();
    ImGui::SetCursorPos(ImVec2(pmin.x - wp.x, pmin.y - wp.y));
    ImGui::SetNextItemAllowOverlap();
    ImGui::PushID("##chat_agent_pill_root");
    ImGui::InvisibleButton("##aida_agent_pill", ImVec2(pill_w, pill_h));
    bool hov = ImGui::IsItemHovered();
    bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
    anim.hover += ((hov ? 1.f : 0.f) - anim.hover) * std::min(12.f * dt, 1.f);

    ImU32 fill = aida::ui::with_alpha(th.panel_header, (0.78f + 0.14f * anim.hover) * alpha);
    ImU32 border_col = aida::ui::with_alpha(th.border_strong,
        (0.65f + 0.35f * anim.hover) * alpha);
    dl->AddRectFilled(pmin, pmax, fill, pill_h * 0.5f);
    dl->AddRect(pmin, pmax, border_col, pill_h * 0.5f, 0, 1.f);

    float dot_cx = pmin.x + pad_x + dot_r;
    float dot_cy = pmin.y + pill_h * 0.5f;
    int br = (bg >> 0) & 0xFF;
    int bg_g = (bg >> 8) & 0xFF;
    int bb_v = (bg >> 16) & 0xFF;
    ImU32 dot_col = IM_COL32(br, bg_g, bb_v, static_cast<int>(((bg >> 24) & 0xFF) * alpha));
    aida::ui::status_dot(ImVec2(dot_cx, dot_cy), dot_r, dot_col, false, 1.4f);

    ImU32 text_col = aida::ui::with_alpha(th.text_primary,
        (0.86f + 0.14f * anim.hover) * alpha);
    float text_x = pmin.x + pad_x + dot_block;
    dl->AddText(ImVec2(text_x, pmin.y + (pill_h - ts.y) * 0.5f), text_col, label.c_str());

    float cx_chev = text_x + ts.x + gap + chev_w * 0.5f;
    float cy_chev = pmin.y + pill_h * 0.5f;
    ImU32 chev_col = aida::ui::with_alpha(th.text_secondary,
        (0.7f + 0.3f * anim.hover) * alpha);
    dl->AddLine(ImVec2(cx_chev - 3.f, cy_chev - 1.5f), ImVec2(cx_chev, cy_chev + 1.5f), chev_col, 1.4f);
    dl->AddLine(ImVec2(cx_chev, cy_chev + 1.5f), ImVec2(cx_chev + 3.f, cy_chev - 1.5f), chev_col, 1.4f);

    if (hov) {
        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
        ImGui::SetTooltip("Active agent: %s\nClick to switch  |  Ctrl+Shift+M to toggle plan/build  |  Ctrl+Shift+A to open picker",
            aida::agent::active_agent_name().c_str());
    }
    if (clicked) {
        aida::agent_picker::open();
    }
    ImGui::PopID();
}

namespace {

struct model_picker_anim_t
{
    float popup_alpha = 0.f;
    float hover = 0.f;
};

model_picker_anim_t& model_picker_anim()
{
    static model_picker_anim_t s;
    return s;
}

std::string truncate_to_width(const std::string& s, float max_w)
{
    if (s.empty()) return s;
    ImVec2 ts = ImGui::CalcTextSize(s.c_str());
    if (ts.x <= max_w) return s;
    std::string out = s;
    while (out.size() > 1) {
        out.pop_back();
        std::string cand = out + "...";
        if (ImGui::CalcTextSize(cand.c_str()).x <= max_w) return cand;
    }
    return std::string("...");
}

std::string compose_provider_display_name(const std::string& provider_id)
{
    if (provider_id.empty()) return std::string();
    const auto* prov = aida::provider::catalog::get_provider(provider_id);
    if (prov != nullptr && !prov->name.empty()) return prov->name;
    return provider_id;
}

std::string compose_model_label()
{
    const std::string provider_id = g_sa_settings.selected_provider_id();
    const std::string model_id    = g_sa_settings.selected_model_id();
    if (provider_id.empty() || model_id.empty())
        return std::string("Select model");
    const auto* model = aida::provider::catalog::get_model(provider_id, model_id);
    const std::string m_disp = (model != nullptr && !model->name.empty()) ? model->name : model_id;
    const std::string p_disp = compose_provider_display_name(provider_id);
    if (p_disp.empty() || p_disp == m_disp) return m_disp;
    return p_disp + "  -  " + m_disp;
}

std::string format_cost_brief(double in_per_million, double out_per_million)
{
    if (in_per_million <= 0.0 && out_per_million <= 0.0) return std::string();
    char buf[64];
    std::snprintf(buf, sizeof(buf), "$%.2f / $%.2f", in_per_million, out_per_million);
    return std::string(buf);
}

std::string format_context_brief(int64_t ctx)
{
    if (ctx <= 0) return std::string();
    char buf[32];
    if (ctx >= 1000000) std::snprintf(buf, sizeof(buf), "%.1fM ctx", static_cast<double>(ctx) / 1000000.0);
    else if (ctx >= 1000) std::snprintf(buf, sizeof(buf), "%lldK ctx", static_cast<long long>(ctx / 1000));
    else std::snprintf(buf, sizeof(buf), "%lld ctx", static_cast<long long>(ctx));
    return std::string(buf);
}

}

float chat_model_pill_width()
{
    std::string lbl = compose_model_label();
    float max_lbl_w = 240.f;
    lbl = truncate_to_width(lbl, max_lbl_w);
    ImVec2 ts = ImGui::CalcTextSize(lbl.c_str());
    float dot_block = 8.f + 6.f;
    const std::string provider_id = g_sa_settings.selected_provider_id();
    const bool authed = !provider_id.empty() && aida::auth_view::is_provider_authenticated(provider_id);
    float trailing = authed ? (6.f + 10.f) : (8.f + 56.f + 6.f + 10.f);
    return 12.f + dot_block + ts.x + trailing + 12.f;
}

void chat_render_model_pill(float anchor_x, float anchor_y, float alpha)
{
    if (alpha <= 0.001f) return;

    const auto& th = aida::ui::resolved();
    auto& anim = model_picker_anim();
    float dt = ImGui::GetIO().DeltaTime;

    const std::string current_provider = g_sa_settings.selected_provider_id();
    const std::string current_model    = g_sa_settings.selected_model_id();
    std::string label = compose_model_label();
    const float max_label_w = 240.f;
    label = truncate_to_width(label, max_label_w);
    ImVec2 ts = ImGui::CalcTextSize(label.c_str());

    const bool has_selection = !current_provider.empty() && !current_model.empty();
    const bool authed = has_selection && aida::auth_view::is_provider_authenticated(current_provider);

    const float pill_h = 22.f;
    const float pad_x = 12.f;
    const float dot_r = 4.f;
    const float dot_block = dot_r * 2.f + 6.f;
    const float gap = 6.f;
    const float chev_w = 10.f;
    const float signin_w = (has_selection && !authed) ? 56.f : 0.f;
    const float signin_gap = signin_w > 0.f ? 8.f : 0.f;
    const float pill_w = pad_x + dot_block + ts.x + signin_gap + signin_w + gap + chev_w + pad_x;

    ImVec2 pmin(anchor_x, anchor_y);
    ImVec2 pmax(anchor_x + pill_w, anchor_y + pill_h);

    ImVec2 wp = ImGui::GetWindowPos();
    ImGui::SetCursorPos(ImVec2(pmin.x - wp.x, pmin.y - wp.y));
    ImGui::SetNextItemAllowOverlap();
    ImGui::PushID("##chat_model_pill_root");
    ImGui::InvisibleButton("##chat_model_pill", ImVec2(pill_w, pill_h));
    bool hov = ImGui::IsItemHovered();
    bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
    anim.hover += ((hov ? 1.f : 0.f) - anim.hover) * std::min(12.f * dt, 1.f);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImU32 fill = aida::ui::with_alpha(th.panel_header, (0.78f + 0.14f * anim.hover) * alpha);
    ImU32 border_col = has_selection
        ? aida::ui::with_alpha(authed ? th.border_strong : th.warning,
              (0.55f + 0.45f * anim.hover) * alpha)
        : aida::ui::with_alpha(th.border_strong, (0.55f + 0.45f * anim.hover) * alpha);
    dl->AddRectFilled(pmin, pmax, fill, pill_h * 0.5f);
    dl->AddRect(pmin, pmax, border_col, pill_h * 0.5f, 0, 1.f);

    float dot_cx = pmin.x + pad_x + dot_r;
    float dot_cy = pmin.y + pill_h * 0.5f;
    ImU32 dot_col;
    if (!has_selection) dot_col = aida::ui::with_alpha(th.text_dim, alpha);
    else if (authed)    dot_col = aida::ui::with_alpha(th.success, alpha);
    else                dot_col = aida::ui::with_alpha(th.warning, alpha);
    aida::ui::status_dot(ImVec2(dot_cx, dot_cy), dot_r, dot_col, authed || !has_selection ? false : true, 1.4f);

    ImU32 text_col = aida::ui::with_alpha(th.text_primary, (0.86f + 0.14f * anim.hover) * alpha);
    float text_x = pmin.x + pad_x + dot_block;
    dl->AddText(ImVec2(text_x, pmin.y + (pill_h - ts.y) * 0.5f), text_col, label.c_str());

    float cursor_after_label = text_x + ts.x + signin_gap;
    bool signin_clicked = false;
    if (signin_w > 0.f) {
        ImGui::SetCursorPos(ImVec2(cursor_after_label - wp.x, pmin.y + 2.f - wp.y));
        ImGui::SetNextItemAllowOverlap();
        ImGui::PushID("##chat_model_pill_signin");
        ImGui::InvisibleButton("##signin_hit", ImVec2(signin_w, pill_h - 4.f));
        bool s_hov = ImGui::IsItemHovered();
        signin_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
        ImVec2 ba(cursor_after_label, pmin.y + 3.f);
        ImVec2 bb(cursor_after_label + signin_w, pmin.y + pill_h - 3.f);
        ImU32 b_fill = aida::ui::with_alpha(th.warning, (s_hov ? 0.85f : 0.55f) * alpha);
        dl->AddRectFilled(ba, bb, b_fill, (pill_h - 6.f) * 0.5f);
        dl->AddRect(ba, bb, aida::ui::with_alpha(th.warning, alpha),
            (pill_h - 6.f) * 0.5f, 0, 1.f);
        const char* sl = "Sign in";
        ImVec2 sts = ImGui::CalcTextSize(sl);
        dl->AddText(ImVec2(ba.x + (signin_w - sts.x) * 0.5f, ba.y + (bb.y - ba.y - sts.y) * 0.5f),
            aida::ui::with_alpha(IM_COL32(20, 20, 30, 250), alpha), sl);
        if (s_hov) ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
        ImGui::PopID();
    }

    float cx_chev = cursor_after_label + signin_w + gap + chev_w * 0.5f;
    float cy_chev = pmin.y + pill_h * 0.5f;
    ImU32 chev_col = aida::ui::with_alpha(th.text_secondary, (0.7f + 0.3f * anim.hover) * alpha);
    dl->AddLine(ImVec2(cx_chev - 3.f, cy_chev - 1.5f), ImVec2(cx_chev, cy_chev + 1.5f), chev_col, 1.4f);
    dl->AddLine(ImVec2(cx_chev, cy_chev + 1.5f), ImVec2(cx_chev + 3.f, cy_chev - 1.5f), chev_col, 1.4f);

    if (hov) {
        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
        const std::string tip_provider = current_provider.empty() ? std::string("none") : current_provider;
        const std::string tip_model = current_model.empty() ? std::string("none") : current_model;
        const char* auth_label = !has_selection ? "no selection"
            : (authed ? "authenticated" : "not signed in");
        ImGui::SetTooltip("Provider: %s\nModel: %s\nAuth: %s\nClick to change",
            tip_provider.c_str(), tip_model.c_str(), auth_label);
    }
    if (signin_clicked && !current_provider.empty()) {
        aida::settings_overlay::open_to_provider(current_provider);
    } else if (clicked) {
        ImGui::OpenPopup("##chat_model_pill_popup");
    }

    bool popup_open = ImGui::IsPopupOpen("##chat_model_pill_popup");
    float popup_target = popup_open ? 1.f : 0.f;
    anim.popup_alpha += (popup_target - anim.popup_alpha) * std::min(14.f * dt, 1.f);

    const float popup_gap = 6.f;
    const float popup_min_h = 140.f;
    const float popup_max_h_pref = 520.f;
    const float popup_min_w = 320.f;
    const float popup_max_w = 440.f;
    ImVec2 vp_size = ImGui::GetIO().DisplaySize;
    float space_below = vp_size.y - pmax.y - popup_gap - 8.f;
    float space_above = pmin.y - popup_gap - 8.f;
    bool pill_in_lower_half = (pmin.y > vp_size.y * 0.5f);
    bool flip_up = (space_below < popup_min_h) || (pill_in_lower_half && space_above >= popup_min_h);
    float clamp_h = popup_max_h_pref;
    ImVec2 popup_anchor;
    ImVec2 popup_pivot;
    if (flip_up) {
        clamp_h = std::min(popup_max_h_pref, std::max(popup_min_h, space_above));
        popup_anchor = ImVec2(pmin.x, pmin.y - popup_gap);
        popup_pivot = ImVec2(0.f, 1.f);
    } else {
        clamp_h = std::min(popup_max_h_pref, std::max(popup_min_h, space_below));
        popup_anchor = ImVec2(pmin.x, pmax.y + popup_gap);
        popup_pivot = ImVec2(0.f, 0.f);
    }
    ImGui::SetNextWindowPos(popup_anchor, ImGuiCond_Always, popup_pivot);
    ImGui::SetNextWindowSizeConstraints(ImVec2(popup_min_w, popup_min_h), ImVec2(popup_max_w, clamp_h));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 12.f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.f, 10.f));
    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, std::min(anim.popup_alpha * 2.f, 1.f));
    ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.panel_bg, 0.98f)));
    ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.border_strong, 0.9f)));

    if (ImGui::BeginPopup("##chat_model_pill_popup",
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_AlwaysAutoResize))
    {
        static char s_filter[96] = {};

        const auto& providers = aida::provider::catalog::list_providers();

        std::vector<const aida::provider::provider_info_t*> selectable_providers;
        selectable_providers.reserve(providers.size());
        for (const auto& p : providers) {
            if (p.model_ids.empty()) continue;
            bool has_active_model = false;
            for (const auto& mid : p.model_ids) {
                const auto* m = aida::provider::catalog::get_model(p.id, mid);
                if (m == nullptr) continue;
                if (m->status == aida::provider::model_info_t::status_t::deprecated) continue;
                has_active_model = true;
                break;
            }
            if (!has_active_model) continue;
            selectable_providers.push_back(&p);
        }

        std::vector<const aida::provider::provider_info_t*> authenticated_providers;
        authenticated_providers.reserve(selectable_providers.size());
        for (const auto* p : selectable_providers) {
            if (!aida::auth_view::is_provider_authenticated(p->id)) continue;
            authenticated_providers.push_back(p);
        }

        std::string active_provider = current_provider;
        bool active_provider_present = false;
        for (const auto* p : authenticated_providers) {
            if (p->id == active_provider) { active_provider_present = true; break; }
        }
        if (!active_provider_present && !authenticated_providers.empty()) {
            active_provider = authenticated_providers.front()->id;
        }
        if (authenticated_providers.empty()) {
            active_provider.clear();
        }

        const float popup_inner_w = 380.f;

        ImFont* seg_font = aida::ui::fonts::body_strong() ? aida::ui::fonts::body_strong() : ImGui::GetFont();
        float seg_font_size = seg_font->FontSize > 0.f ? seg_font->FontSize : 14.f;
        const float seg_h = 26.f;
        const float seg_pad_x = 12.f;
        const float seg_gap = 6.f;

        if (authenticated_providers.empty()) {
            ImFont* cf_es = aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont();
            float cf_es_size = cf_es->FontSize > 0.f ? cf_es->FontSize : 12.f;
            const char* es_label = "No providers signed in yet";
            ImVec2 es_ts = cf_es->CalcTextSizeA(cf_es_size, FLT_MAX, 0.f, es_label);

            const char* btn_label = "Sign in a provider";
            ImVec2 btn_ts = seg_font->CalcTextSizeA(seg_font_size, FLT_MAX, 0.f, btn_label);
            float btn_w = btn_ts.x + seg_pad_x * 2.f;
            float btn_h = seg_h;

            ImVec2 row_cur = ImGui::GetCursorScreenPos();
            ImDrawList* edl = ImGui::GetWindowDrawList();
            edl->AddText(cf_es, cf_es_size,
                ImVec2(row_cur.x + 2.f, row_cur.y + (btn_h - cf_es_size) * 0.5f),
                aida::ui::with_alpha(th.text_dim, 0.95f),
                es_label);

            ImGui::SetCursorScreenPos(ImVec2(row_cur.x + es_ts.x + 12.f, row_cur.y));
            ImGui::SetNextItemAllowOverlap();
            ImGui::PushID("##chat_model_pill_signin_empty_state");
            ImGui::InvisibleButton("##signin_empty_btn", ImVec2(btn_w, btn_h));
            bool b_hov = ImGui::IsItemHovered();
            bool b_click = ImGui::IsItemClicked(ImGuiMouseButton_Left);
            ImVec2 ba(row_cur.x + es_ts.x + 12.f, row_cur.y);
            ImVec2 bb(ba.x + btn_w, ba.y + btn_h);
            ImU32 b_fill = aida::ui::with_alpha(th.accent_u32, b_hov ? 0.95f : 0.75f);
            ImU32 b_border = aida::ui::with_alpha(th.accent_hover, b_hov ? 1.f : 0.7f);
            edl->AddRectFilled(ba, bb, b_fill, btn_h * 0.5f);
            edl->AddRect(ba, bb, b_border, btn_h * 0.5f, 0, 1.f);
            edl->AddText(seg_font, seg_font_size,
                ImVec2(ba.x + seg_pad_x, ba.y + (btn_h - seg_font_size) * 0.5f - 0.5f),
                aida::ui::with_alpha(IM_COL32(20, 20, 30, 250), 1.f),
                btn_label);
            if (b_hov) ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
            if (b_click) {
                aida::settings_overlay::open();
                aida::settings_overlay::set_active_tab(aida::settings_overlay::tab_accounts);
                ImGui::CloseCurrentPopup();
            }
            ImGui::PopID();

            ImGui::SetCursorScreenPos(ImVec2(row_cur.x, row_cur.y));
            ImGui::Dummy(ImVec2(popup_inner_w, btn_h + 4.f));
        } else {
            ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.f, 0.f, 0.f, 0.f));
            ImGui::BeginChild("##chat_model_pill_provider_strip",
                ImVec2(popup_inner_w, seg_h + 4.f),
                false,
                ImGuiWindowFlags_NoBackground |
                ImGuiWindowFlags_HorizontalScrollbar |
                ImGuiWindowFlags_NoScrollWithMouse);

            float strip_cursor_x = ImGui::GetCursorScreenPos().x;
            float strip_cursor_y = ImGui::GetCursorScreenPos().y;
            ImDrawList* sdl = ImGui::GetWindowDrawList();
            float total_strip_w = 0.f;

            for (std::size_t i = 0; i < authenticated_providers.size(); ++i) {
                const auto* p = authenticated_providers[i];
                const std::string label = p->name.empty() ? p->id : p->name;
                ImVec2 lts = seg_font->CalcTextSizeA(seg_font_size, FLT_MAX, 0.f, label.c_str());
                float chip_w = lts.x + seg_pad_x * 2.f;

                ImGui::PushID(static_cast<int>(i));
                ImGui::PushID((std::string("##prov_chip_") + p->id).c_str());
                ImGui::SetCursorScreenPos(ImVec2(strip_cursor_x + total_strip_w, strip_cursor_y));
                ImGui::SetNextItemAllowOverlap();
                ImGui::InvisibleButton("##prov_chip_btn", ImVec2(chip_w, seg_h));
                bool ch_hov = ImGui::IsItemHovered();
                bool ch_click = ImGui::IsItemClicked(ImGuiMouseButton_Left);

                const bool is_active = (active_provider == p->id);

                ImVec2 ca(strip_cursor_x + total_strip_w, strip_cursor_y);
                ImVec2 cb(ca.x + chip_w, ca.y + seg_h);
                ImU32 chip_fill = is_active
                    ? aida::ui::with_alpha(th.selection_strong, 0.85f)
                    : aida::ui::with_alpha(th.panel_header, ch_hov ? 0.95f : 0.65f);
                ImU32 chip_border = is_active
                    ? aida::ui::with_alpha(th.accent_u32, 0.9f)
                    : aida::ui::with_alpha(th.border_subtle, ch_hov ? 0.9f : 0.55f);
                sdl->AddRectFilled(ca, cb, chip_fill, seg_h * 0.5f);
                sdl->AddRect(ca, cb, chip_border, seg_h * 0.5f, 0, 1.f);

                ImU32 chip_text_col = aida::ui::with_alpha(
                    is_active ? th.accent_hover : th.text_secondary,
                    is_active ? 1.f : (ch_hov ? 1.f : 0.9f));
                sdl->AddText(seg_font, seg_font_size,
                    ImVec2(ca.x + seg_pad_x, ca.y + (seg_h - seg_font_size) * 0.5f - 0.5f),
                    chip_text_col, label.c_str());

                const float dot_r = 3.f;
                ImU32 dot_col = aida::ui::with_alpha(th.success, is_active ? 1.f : 0.85f);
                sdl->AddCircleFilled(ImVec2(cb.x - seg_pad_x * 0.5f, ca.y + seg_h * 0.5f), dot_r, dot_col);

                if (ch_hov) {
                    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                    ImGui::SetTooltip("%s\nauthenticated", label.c_str());
                }
                if (ch_click) {
                    g_sa_settings.default_provider_id = p->id;
                    g_sa_settings.save();
                    active_provider = p->id;
                    s_filter[0] = '\0';
                }

                ImGui::PopID();
                ImGui::PopID();
                total_strip_w += chip_w + (i + 1 < authenticated_providers.size() ? seg_gap : 0.f);
            }

            ImGui::SetCursorScreenPos(ImVec2(strip_cursor_x, strip_cursor_y));
            ImGui::Dummy(ImVec2(total_strip_w, seg_h));
            ImGui::EndChild();
            ImGui::PopStyleColor();
        }

        ImGui::Spacing();

        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10.f, 6.f));
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.bg_overlay, 0.9f)));
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(th.text_primary));
        ImGui::SetNextItemWidth(popup_inner_w);
        if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
        ImGui::InputTextWithHint("##chat_model_pill_filter", "Search models...", s_filter, sizeof(s_filter));
        ImGui::PopStyleColor(2);
        ImGui::PopStyleVar(2);

        std::string filter_lower;
        for (const char* p = s_filter; *p; ++p)
            filter_lower += static_cast<char>(std::tolower(static_cast<unsigned char>(*p)));

        ImGui::Spacing();

        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.f, 0.f, 0.f, 0.f));
        float list_h = std::max(140.f, std::min(400.f, clamp_h - 60.f - seg_h - 10.f));
        ImGui::BeginChild("##chat_model_pill_list", ImVec2(popup_inner_w, list_h), false, ImGuiWindowFlags_NoBackground);

        bool any_model_match = false;
        const aida::provider::provider_info_t* active_p = nullptr;
        for (const auto* p : selectable_providers) {
            if (p->id == active_provider) { active_p = p; break; }
        }

        if (active_p != nullptr) {
            std::vector<const aida::provider::model_info_t*> visible;
            visible.reserve(active_p->model_ids.size());
            for (const auto& mid : active_p->model_ids) {
                const auto* m = aida::provider::catalog::get_model(active_p->id, mid);
                if (m == nullptr) continue;
                if (m->status == aida::provider::model_info_t::status_t::deprecated) continue;
                if (!filter_lower.empty()) {
                    std::string name_lower = m->name;
                    std::string id_lower   = m->id;
                    for (auto& c : name_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                    for (auto& c : id_lower)   c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                    if (name_lower.find(filter_lower) == std::string::npos &&
                        id_lower.find(filter_lower) == std::string::npos)
                        continue;
                }
                visible.push_back(m);
                any_model_match = true;
            }

            for (std::size_t mi = 0; mi < visible.size(); ++mi) {
                const auto* m = visible[mi];
                const bool is_sel = (current_provider == active_p->id) && (current_model == m->id);
                ImGui::PushID(static_cast<int>(mi));
                ImGui::PushID((active_p->id + "/" + m->id).c_str());

                ImVec2 row_cur = ImGui::GetCursorScreenPos();
                float row_w = 372.f;
                float row_h = 36.f;
                ImGui::SetNextItemAllowOverlap();
                ImGui::InvisibleButton("##chat_model_row", ImVec2(row_w, row_h));
                bool row_hov = ImGui::IsItemHovered();
                bool row_click = ImGui::IsItemClicked();

                ImDrawList* rdl = ImGui::GetWindowDrawList();
                ImVec2 ra = row_cur;
                ImVec2 rb(row_cur.x + row_w, row_cur.y + row_h);
                ImU32 row_bg = is_sel
                    ? aida::ui::with_alpha(th.selection_strong, 0.65f)
                    : (row_hov ? aida::ui::with_alpha(th.hover_wash, 1.f) : IM_COL32(0, 0, 0, 0));
                rdl->AddRectFilled(ra, rb, row_bg, 8.f);
                if (is_sel) {
                    rdl->AddRect(ra, rb, aida::ui::with_alpha(th.accent_u32, 0.85f), 8.f, 0, 1.f);
                }

                ImFont* nf = aida::ui::fonts::body_strong() ? aida::ui::fonts::body_strong() : ImGui::GetFont();
                ImFont* cf = aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont();
                float nf_size = nf->FontSize > 0.f ? nf->FontSize : 14.f;
                float cf_size = cf->FontSize > 0.f ? cf->FontSize : 12.f;

                rdl->AddText(nf, nf_size,
                    ImVec2(ra.x + 10.f, ra.y + 4.f),
                    aida::ui::with_alpha(is_sel ? th.accent_hover : th.text_primary, 1.f),
                    m->name.c_str());

                const std::string ctx_str = format_context_brief(m->limit.context);
                const std::string cost_str = format_cost_brief(m->cost.input_per_million, m->cost.output_per_million);
                std::string meta;
                if (!ctx_str.empty()) meta = ctx_str;
                if (!cost_str.empty()) {
                    if (!meta.empty()) meta += "  ";
                    meta += cost_str;
                }
                if (!meta.empty()) {
                    rdl->AddText(cf, cf_size,
                        ImVec2(ra.x + 10.f, ra.y + 4.f + nf_size + 1.f),
                        aida::ui::with_alpha(th.text_dim, 0.95f),
                        meta.c_str());
                }

                if (m->capabilities.reasoning) {
                    const char* tag = "reason";
                    ImVec2 tag_ts = cf->CalcTextSizeA(cf_size, FLT_MAX, 0.f, tag);
                    float tag_pad = 6.f;
                    float tag_w = tag_ts.x + tag_pad * 2.f;
                    float tag_h = cf_size + 6.f;
                    ImVec2 ta(rb.x - tag_w - 8.f, ra.y + (row_h - tag_h) * 0.5f);
                    ImVec2 tb(ta.x + tag_w, ta.y + tag_h);
                    rdl->AddRectFilled(ta, tb, aida::ui::with_alpha(th.info, 0.22f), tag_h * 0.5f);
                    rdl->AddRect(ta, tb, aida::ui::with_alpha(th.info, 0.55f), tag_h * 0.5f, 0, 1.f);
                    rdl->AddText(cf, cf_size,
                        ImVec2(ta.x + tag_pad, ta.y + (tag_h - cf_size) * 0.5f - 0.5f),
                        aida::ui::with_alpha(th.info, 1.f), tag);
                }

                if (row_hov) ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                if (row_click) {
                    g_sa_settings.set_selection(active_p->id, m->id);
                    auto* prof = g_sa_settings.get_active_profile();
                    if (prof != nullptr) {
                        prof->model = m->id;
                        g_sa_settings.sync_legacy_fields_from_active_profile();
                    }
                    g_sa_settings.save();
                    aida::events::model_changed_t evt;
                    evt.session_id = chat_active_session();
                    evt.provider_id = active_p->id;
                    evt.model_id    = m->id;
                    aida::events::publish(aida::events::event_model_changed, evt);
                    ImGui::CloseCurrentPopup();
                }
                ImGui::PopID();
                ImGui::PopID();
            }
        }

        if (!any_model_match) {
            ImGui::Spacing();
            ImFont* cf = aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont();
            float cf_size = cf->FontSize > 0.f ? cf->FontSize : 12.f;
            ImVec2 cur = ImGui::GetCursorScreenPos();
            ImGui::GetWindowDrawList()->AddText(cf, cf_size,
                ImVec2(cur.x + 8.f, cur.y + 4.f),
                aida::ui::with_alpha(th.text_dim, 0.9f),
                active_p == nullptr ? "No providers available" : "No matching models");
            ImGui::Dummy(ImVec2(1.f, cf_size + 12.f));
        }

        ImGui::EndChild();
        ImGui::PopStyleColor();

        ImGui::EndPopup();
    }
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar(3);
    ImGui::PopID();
}

namespace {

struct skills_pill_anim_t
{
    float popup_alpha = 0.f;
    float hover = 0.f;
};

skills_pill_anim_t& skills_pill_anim()
{
    static skills_pill_anim_t s;
    return s;
}

}

float chat_skills_pill_width()
{
    const char* lbl = "Skills";
    ImVec2 ts = ImGui::CalcTextSize(lbl);
    return ts.x + 12.f + 6.f + 10.f + 12.f;
}

void chat_render_skills_pill(float anchor_x, float anchor_y, float alpha, char* chat_buf, std::size_t chat_buf_size)
{
    if (alpha <= 0.001f) return;
    if (chat_buf == nullptr || chat_buf_size == 0) return;

    const auto& th = aida::ui::resolved();
    auto& anim = skills_pill_anim();
    float dt = ImGui::GetIO().DeltaTime;

    const char* lbl = "Skills";
    ImVec2 ts = ImGui::CalcTextSize(lbl);
    float pill_h = 22.f;
    float pad_x = 12.f;
    float chev_w = 10.f;
    float gap = 6.f;
    float pill_w = pad_x + ts.x + gap + chev_w + pad_x;

    ImVec2 pmin(anchor_x, anchor_y);
    ImVec2 pmax(anchor_x + pill_w, anchor_y + pill_h);

    ImVec2 wp = ImGui::GetWindowPos();
    ImGui::SetCursorPos(ImVec2(pmin.x - wp.x, pmin.y - wp.y));
    ImGui::SetNextItemAllowOverlap();
    ImGui::PushID("##chat_skills_pill_root");
    ImGui::InvisibleButton("##chat_skills_pill", ImVec2(pill_w, pill_h));
    bool hov = ImGui::IsItemHovered();
    bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
    anim.hover += ((hov ? 1.f : 0.f) - anim.hover) * std::min(12.f * dt, 1.f);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImU32 fill = aida::ui::with_alpha(th.panel_header, (0.72f + 0.14f * anim.hover) * alpha);
    ImU32 border = aida::ui::with_alpha(th.border_subtle, (0.6f + 0.4f * anim.hover) * alpha);
    dl->AddRectFilled(pmin, pmax, fill, pill_h * 0.5f);
    dl->AddRect(pmin, pmax, border, pill_h * 0.5f, 0, 1.f);

    ImU32 text_col = aida::ui::with_alpha(th.text_secondary, (0.86f + 0.14f * anim.hover) * alpha);
    dl->AddText(ImVec2(pmin.x + pad_x, pmin.y + (pill_h - ts.y) * 0.5f), text_col, lbl);

    float cx_chev = pmin.x + pad_x + ts.x + gap + chev_w * 0.5f;
    float cy_chev = pmin.y + pill_h * 0.5f;
    ImU32 chev_col = aida::ui::with_alpha(th.text_dim, (0.7f + 0.3f * anim.hover) * alpha);
    dl->AddLine(ImVec2(cx_chev - 3.f, cy_chev - 1.5f), ImVec2(cx_chev, cy_chev + 1.5f), chev_col, 1.4f);
    dl->AddLine(ImVec2(cx_chev, cy_chev + 1.5f), ImVec2(cx_chev + 3.f, cy_chev - 1.5f), chev_col, 1.4f);

    if (hov) {
        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
        ImGui::SetTooltip("Insert a /skill command");
    }
    if (clicked) {
        ImGui::OpenPopup("##chat_skills_pill_popup");
    }

    bool popup_open = ImGui::IsPopupOpen("##chat_skills_pill_popup");
    float popup_target = popup_open ? 1.f : 0.f;
    anim.popup_alpha += (popup_target - anim.popup_alpha) * std::min(14.f * dt, 1.f);

    const float popup_gap = 6.f;
    const float popup_min_h = 120.f;
    const float popup_max_h_pref = 460.f;
    const float popup_min_w = 280.f;
    const float popup_max_w = 420.f;
    ImVec2 vp_size = ImGui::GetIO().DisplaySize;
    float space_below = vp_size.y - pmax.y - popup_gap - 8.f;
    float space_above = pmin.y - popup_gap - 8.f;
    bool pill_in_lower_half = (pmin.y > vp_size.y * 0.5f);
    bool flip_up = (space_below < popup_min_h) || (pill_in_lower_half && space_above >= popup_min_h);
    float clamp_h = popup_max_h_pref;
    ImVec2 popup_anchor;
    ImVec2 popup_pivot;
    if (flip_up) {
        clamp_h = std::min(popup_max_h_pref, std::max(popup_min_h, space_above));
        popup_anchor = ImVec2(pmin.x, pmin.y - popup_gap);
        popup_pivot = ImVec2(0.f, 1.f);
    } else {
        clamp_h = std::min(popup_max_h_pref, std::max(popup_min_h, space_below));
        popup_anchor = ImVec2(pmin.x, pmax.y + popup_gap);
        popup_pivot = ImVec2(0.f, 0.f);
    }
    ImGui::SetNextWindowPos(popup_anchor, ImGuiCond_Always, popup_pivot);
    ImGui::SetNextWindowSizeConstraints(ImVec2(popup_min_w, popup_min_h), ImVec2(popup_max_w, clamp_h));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 12.f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.f, 10.f));
    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, std::min(anim.popup_alpha * 2.f, 1.f));
    ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.panel_bg, 0.98f)));
    ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.border_strong, 0.9f)));

    if (ImGui::BeginPopup("##chat_skills_pill_popup",
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_AlwaysAutoResize))
    {
        static char s_filter[96] = {};

        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10.f, 6.f));
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.bg_overlay, 0.9f)));
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(th.text_primary));
        ImGui::SetNextItemWidth(360.f);
        if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
        ImGui::InputTextWithHint("##chat_skills_filter", "Search skills...", s_filter, sizeof(s_filter));
        ImGui::PopStyleColor(2);
        ImGui::PopStyleVar(2);

        std::string filter_lower;
        for (const char* p = s_filter; *p; ++p)
            filter_lower += static_cast<char>(std::tolower(static_cast<unsigned char>(*p)));

        ImGui::Spacing();
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.f, 0.f, 0.f, 0.f));
        float list_h = std::max(120.f, std::min(320.f, clamp_h - 60.f));
        ImGui::BeginChild("##chat_skills_list", ImVec2(360.f, list_h), false, ImGuiWindowFlags_NoBackground);

        std::vector<aida::skills::skill_metadata_t> skills_all = aida::skills::all();
        std::string active_agent = aida::agent::active_agent_name();

        std::vector<const aida::skills::skill_metadata_t*> matching;
        matching.reserve(skills_all.size());
        for (const auto& sk : skills_all) {
            if (!aida::skills::is_enabled(sk.name)) continue;
            if (!sk.agent_slugs.empty()) {
                bool ok = false;
                for (const auto& slug : sk.agent_slugs) {
                    if (slug == active_agent) { ok = true; break; }
                }
                if (!ok) continue;
            }
            if (!filter_lower.empty()) {
                std::string name_lower = sk.name;
                std::string desc_lower = sk.description;
                for (auto& c : name_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                for (auto& c : desc_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                if (name_lower.find(filter_lower) == std::string::npos &&
                    desc_lower.find(filter_lower) == std::string::npos)
                    continue;
            }
            matching.push_back(&sk);
        }

        ImDrawList* sdl = ImGui::GetWindowDrawList();
        ImFont* nf = aida::ui::fonts::body_strong() ? aida::ui::fonts::body_strong() : ImGui::GetFont();
        ImFont* cf = aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont();
        float nf_size = nf->FontSize > 0.f ? nf->FontSize : 14.f;
        float cf_size = cf->FontSize > 0.f ? cf->FontSize : 12.f;

        if (matching.empty()) {
            ImVec2 cur = ImGui::GetCursorScreenPos();
            sdl->AddText(cf, cf_size,
                ImVec2(cur.x + 8.f, cur.y + 4.f),
                aida::ui::with_alpha(th.text_dim, 0.9f),
                filter_lower.empty() ? "No skills available for this agent" : "No matching skills");
            ImGui::Dummy(ImVec2(1.f, cf_size + 12.f));
        }
        for (std::size_t row_idx = 0; row_idx < matching.size(); ++row_idx) {
            const auto* sk = matching[row_idx];
            ImGui::PushID(static_cast<int>(row_idx));
            ImGui::PushID(sk->name.c_str());
            ImVec2 row_cur = ImGui::GetCursorScreenPos();
            float row_w = 340.f;
            float row_h = 40.f;
            ImGui::SetNextItemAllowOverlap();
            ImGui::InvisibleButton("##skill_row", ImVec2(row_w, row_h));
            bool row_hov = ImGui::IsItemHovered();
            bool row_click = ImGui::IsItemClicked();

            ImVec2 ra = row_cur;
            ImVec2 rb(row_cur.x + row_w, row_cur.y + row_h);
            ImU32 row_bg = row_hov ? aida::ui::with_alpha(th.hover_wash, 1.f) : IM_COL32(0, 0, 0, 0);
            sdl->AddRectFilled(ra, rb, row_bg, 8.f);

            std::string nm = std::string("/") + sk->name;
            sdl->AddText(nf, nf_size,
                ImVec2(ra.x + 10.f, ra.y + 5.f),
                aida::ui::with_alpha(th.text_primary, 1.f), nm.c_str());

            if (!sk->description.empty()) {
                std::string desc = sk->description;
                if (desc.size() > 72) { desc.resize(69); desc.append("..."); }
                sdl->AddText(cf, cf_size,
                    ImVec2(ra.x + 10.f, ra.y + 5.f + nf_size + 1.f),
                    aida::ui::with_alpha(th.text_dim, 0.95f), desc.c_str());
            }

            if (row_hov) ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
            if (row_click) {
                std::string injection = std::string("/") + sk->name + " ";
                std::size_t cur_len = std::strlen(chat_buf);
                if (cur_len == 0 || (cur_len == 1 && chat_buf[0] == '/')) {
                    std::size_t copy = std::min(injection.size(), chat_buf_size - 1);
                    std::memcpy(chat_buf, injection.data(), copy);
                    chat_buf[copy] = '\0';
                } else {
                    if (cur_len + injection.size() + 1 < chat_buf_size) {
                        chat_buf[cur_len] = '\n';
                        std::memcpy(chat_buf + cur_len + 1, injection.data(), injection.size());
                        chat_buf[cur_len + 1 + injection.size()] = '\0';
                    } else {
                        std::size_t copy = std::min(injection.size(), chat_buf_size - 1);
                        std::memcpy(chat_buf, injection.data(), copy);
                        chat_buf[copy] = '\0';
                    }
                }
                ImGui::CloseCurrentPopup();
            }
            ImGui::PopID();
            ImGui::PopID();
        }

        ImGui::EndChild();
        ImGui::PopStyleColor();

        ImGui::EndPopup();
    }
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar(3);
    ImGui::PopID();
}

namespace {

struct mcp_pill_anim_t
{
    float hover = 0.f;
    float popup_alpha = 0.f;
};

mcp_pill_anim_t& mcp_pill_anim()
{
    static mcp_pill_anim_t s;
    return s;
}

}

float chat_mcp_pill_width()
{
    const char* lbl = "MCP";
    ImVec2 ts = ImGui::CalcTextSize(lbl);
    return ts.x + 12.f + 6.f + 8.f + 12.f;
}

void chat_render_mcp_pill(float anchor_x, float anchor_y, float alpha)
{
    if (alpha <= 0.001f) return;

    const auto& th = aida::ui::resolved();
    auto& anim = mcp_pill_anim();
    float dt = ImGui::GetIO().DeltaTime;

    auto& mgr = get_mcp_client_manager();
    auto statuses = mgr.get_status();
    int connected = 0;
    int total = static_cast<int>(statuses.size());
    int tools_count = 0;
    for (const auto& s : statuses) {
        if (s.state == mcp_client::connection_state_t::connected) {
            connected++;
            tools_count += static_cast<int>(s.tool_count);
        }
    }

    char label_buf[32];
    if (total == 0) std::snprintf(label_buf, sizeof(label_buf), "MCP");
    else std::snprintf(label_buf, sizeof(label_buf), "MCP %d/%d", connected, total);

    ImVec2 ts = ImGui::CalcTextSize(label_buf);
    float pill_h = 22.f;
    float pad_x = 12.f;
    float dot_w = 8.f;
    float gap = 6.f;
    float pill_w = pad_x + dot_w + gap + ts.x + pad_x;

    ImVec2 pmin(anchor_x, anchor_y);
    ImVec2 pmax(anchor_x + pill_w, anchor_y + pill_h);

    ImVec2 wp = ImGui::GetWindowPos();
    ImGui::SetCursorPos(ImVec2(pmin.x - wp.x, pmin.y - wp.y));
    ImGui::SetNextItemAllowOverlap();
    ImGui::PushID("##chat_mcp_pill_root");
    ImGui::InvisibleButton("##chat_mcp_pill", ImVec2(pill_w, pill_h));
    bool hov = ImGui::IsItemHovered();
    bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
    anim.hover += ((hov ? 1.f : 0.f) - anim.hover) * std::min(12.f * dt, 1.f);

    ImU32 status_col;
    if (total == 0) status_col = aida::ui::with_alpha(th.text_dim, 0.85f);
    else if (connected == total) status_col = th.success;
    else if (connected > 0) status_col = th.warning;
    else status_col = th.error;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImU32 fill = aida::ui::with_alpha(th.panel_header, (0.72f + 0.14f * anim.hover) * alpha);
    ImU32 border = aida::ui::with_alpha(th.border_subtle, (0.6f + 0.4f * anim.hover) * alpha);
    dl->AddRectFilled(pmin, pmax, fill, pill_h * 0.5f);
    dl->AddRect(pmin, pmax, border, pill_h * 0.5f, 0, 1.f);

    float dot_cx = pmin.x + pad_x + dot_w * 0.5f;
    float dot_cy = pmin.y + pill_h * 0.5f;
    dl->AddCircleFilled(ImVec2(dot_cx, dot_cy), dot_w * 0.5f, aida::ui::with_alpha(status_col, alpha), 18);

    ImU32 text_col = aida::ui::with_alpha(th.text_secondary, (0.86f + 0.14f * anim.hover) * alpha);
    dl->AddText(ImVec2(dot_cx + dot_w * 0.5f + gap, pmin.y + (pill_h - ts.y) * 0.5f), text_col, label_buf);

    if (hov) {
        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
        char tip[160];
        std::snprintf(tip, sizeof(tip),
            "MCP servers connected: %d / %d\nTotal remote tools: %d\nClick to view details",
            connected, total, tools_count);
        ImGui::SetTooltip("%s", tip);
    }
    if (clicked) {
        ImGui::OpenPopup("##chat_mcp_pill_popup");
    }

    bool popup_open = ImGui::IsPopupOpen("##chat_mcp_pill_popup");
    float popup_target = popup_open ? 1.f : 0.f;
    anim.popup_alpha += (popup_target - anim.popup_alpha) * std::min(14.f * dt, 1.f);

    const float popup_gap = 6.f;
    const float popup_min_h = 100.f;
    const float popup_max_h_pref = 380.f;
    const float popup_min_w = 280.f;
    const float popup_max_w = 420.f;
    ImVec2 vp_size = ImGui::GetIO().DisplaySize;
    float space_below = vp_size.y - pmax.y - popup_gap - 8.f;
    float space_above = pmin.y - popup_gap - 8.f;
    bool pill_in_lower_half = (pmin.y > vp_size.y * 0.5f);
    bool flip_up = (space_below < popup_min_h) || (pill_in_lower_half && space_above >= popup_min_h);
    float clamp_h = popup_max_h_pref;
    ImVec2 popup_anchor;
    ImVec2 popup_pivot;
    if (flip_up) {
        clamp_h = std::min(popup_max_h_pref, std::max(popup_min_h, space_above));
        popup_anchor = ImVec2(pmin.x, pmin.y - popup_gap);
        popup_pivot = ImVec2(0.f, 1.f);
    } else {
        clamp_h = std::min(popup_max_h_pref, std::max(popup_min_h, space_below));
        popup_anchor = ImVec2(pmin.x, pmax.y + popup_gap);
        popup_pivot = ImVec2(0.f, 0.f);
    }
    ImGui::SetNextWindowPos(popup_anchor, ImGuiCond_Always, popup_pivot);
    ImGui::SetNextWindowSizeConstraints(ImVec2(popup_min_w, popup_min_h), ImVec2(popup_max_w, clamp_h));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 12.f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12.f, 10.f));
    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, std::min(anim.popup_alpha * 2.f, 1.f));
    ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.panel_bg, 0.98f)));
    ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.border_strong, 0.9f)));

    if (ImGui::BeginPopup("##chat_mcp_pill_popup",
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_AlwaysAutoResize))
    {
        ImFont* hf = aida::ui::fonts::body_strong() ? aida::ui::fonts::body_strong() : ImGui::GetFont();
        ImFont* cf = aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont();
        float hf_size = hf->FontSize > 0.f ? hf->FontSize : 14.f;
        float cf_size = cf->FontSize > 0.f ? cf->FontSize : 12.f;

        ImDrawList* pdl = ImGui::GetWindowDrawList();
        ImVec2 cur = ImGui::GetCursorScreenPos();
        pdl->AddText(hf, hf_size, cur, aida::ui::with_alpha(th.text_primary, 1.f), "MCP servers");
        ImGui::Dummy(ImVec2(1.f, hf_size + 4.f));

        if (statuses.empty()) {
            ImVec2 ec = ImGui::GetCursorScreenPos();
            pdl->AddText(cf, cf_size, ImVec2(ec.x, ec.y + 2.f),
                aida::ui::with_alpha(th.text_dim, 0.9f),
                "No MCP servers configured");
            ImGui::Dummy(ImVec2(1.f, cf_size + 8.f));
        } else {
            for (const auto& s : statuses) {
                ImVec2 row_cur = ImGui::GetCursorScreenPos();
                float row_w = 360.f;
                float row_h = 32.f;
                ImVec2 ra = row_cur;
                ImVec2 rb(row_cur.x + row_w, row_cur.y + row_h);
                pdl->AddRectFilled(ra, rb, aida::ui::with_alpha(th.panel_header, 0.6f), 8.f);

                ImU32 d_col;
                const char* state_label = "?";
                switch (s.state) {
                    case mcp_client::connection_state_t::connected: d_col = th.success; state_label = "online"; break;
                    case mcp_client::connection_state_t::connecting: d_col = th.warning; state_label = "connecting"; break;
                    case mcp_client::connection_state_t::reconnecting: d_col = th.warning; state_label = "reconnecting"; break;
                    case mcp_client::connection_state_t::disconnected: d_col = th.text_dim; state_label = "offline"; break;
                    case mcp_client::connection_state_t::error: d_col = th.error; state_label = "error"; break;
                    default: d_col = th.text_dim; break;
                }
                pdl->AddCircleFilled(ImVec2(ra.x + 12.f, (ra.y + rb.y) * 0.5f), 4.f, d_col, 14);
                pdl->AddText(hf, hf_size,
                    ImVec2(ra.x + 24.f, ra.y + 3.f),
                    aida::ui::with_alpha(th.text_primary, 1.f), s.name.c_str());

                char meta[96];
                std::snprintf(meta, sizeof(meta), "%s  |  %d tools", state_label, static_cast<int>(s.tool_count));
                pdl->AddText(cf, cf_size,
                    ImVec2(ra.x + 24.f, ra.y + 3.f + hf_size + 1.f),
                    aida::ui::with_alpha(th.text_dim, 0.92f), meta);

                ImGui::Dummy(ImVec2(1.f, row_h + 4.f));
            }
        }

        ImGui::EndPopup();
    }
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar(3);
    ImGui::PopID();
}
