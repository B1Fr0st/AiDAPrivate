
#include <windows.h>
#include <intrin.h>

#include "work_queue.hpp"
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
#include "cost_calculator.hpp"
#include "compaction.hpp"
#include "command_registry.hpp"
#include "session_store.hpp"
#include "provider_catalog.hpp"
#include "zydis_disasm.hpp"
#include "auto_approval.hpp"
#include "file_context_tracker.hpp"
#include "standalone_context.hpp"

#include "../helpers/globals.h"

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


std::thread       s_ai_thread;
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

bool request_tool_approval(const std::string& name, const json& arguments)
{

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
            if (tok == name) return false;
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


        if (arguments.contains("path")) {
            std::string path = arguments["path"].get<std::string>();
            auto ignore_patterns = auto_approval::load_aidaignore(g_sa_settings.aidaignore_path);
            if (auto_approval::matches_aidaignore(path, ignore_patterns))
                return false;
        }


        std::string command;
        if (name == "execute_command" && arguments.contains("command"))
            command = arguments["command"].get<std::string>();

        auto decision = auto_approval::should_auto_approve(
                name, aa_settings, s_approval_counters, command);
        if (decision == auto_approval::approval_decision_t::approve)
            return true;
        if (decision == auto_approval::approval_decision_t::deny)
            return false;
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
            try {
                tr = t.handler(arguments);
            } catch (const std::exception& e) {
                return std::string("Error: ") + e.what();
            } catch (...) {
                return "Error: Unknown exception executing tool.";
            }
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

    {
        uint64_t gate = standalone_license::inline_gate_check(
            standalone_license::gate_chat_pre_agentic);
        if (standalone_license::verify_gate_token(
                standalone_license::gate_chat_pre_agentic, gate) < 0.5) {
            post_update(ai_update_t::ERR,
                standalone_license::decode_status_string(
                    standalone_license::str_session_revoked));
            return;
        }
    }

    if (!standalone_license::is_valid()) {
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
                    tool_results += "\n<tool_result name=\"" + tc.name + "\">\nTool execution denied by user.\n</tool_result>\n";
                    continue;
                }

                std::string result = execute_tool(tc.name, tc.arguments);
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
    for (auto& [role, text] : history) {
        std::string r = (role == "assistant" || role == "Assistant") ? "assistant" : "user";
        messages.push_back({{"role", r}, {"content", text}});
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
            output_log::push(bottom_tab_t::output, std::string("[ai] Exception: ") + e.what());
            post_update(ai_update_t::ERR, std::string("Exception: ") + e.what());
            return;
        }

        budget_used += gen.input_tokens + gen.output_tokens;

        if (s_cancel.load()) { post_update(ai_update_t::COMPLETE); return; }
        if (gen.is_error) { post_update(ai_update_t::ERR, gen.text); return; }

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

        if (!gen.thinking.empty())
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
                tool_result_content.push_back(
                    standalone_ai_client_t::make_tool_result_block(tc.id, "Tool execution denied by user.", true));
                continue;
            }

            std::string result = execute_tool(tc.name, tc.arguments);
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
        g_disasm.file = DisasmFile{};
        if (disasm::load_pe(g_sa_settings.workspace.last_active_path, g_disasm.file))
            disasm::decode_section(g_disasm.file);
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

    if (!driver_bridge::refresh_heartbeat())
        return;

    const DWORD own_pid = GetCurrentProcessId();
    if (!driver_bridge::attach(own_pid))
        return;


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

    driver_bridge::register_dll_protection(
        reinterpret_cast<std::uint64_t>(exe_module),
        text_base,
        text_size,
        text_hash,
        2000
    );
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

    diag::log_tagged("init_chat", "mcp_register_tools_start");
    mcp_standalone::register_standalone_tools(s_mcp_server);
    diag::log_tagged("init_chat", "mcp_register_tools_done");
    if (g_sa_settings.mcp_enabled) {
        diag::log_tagged_fmt("init_chat", "mcp_server_start port=%d", g_sa_settings.mcp_port);
        if (s_mcp_server.start(g_sa_settings.mcp_port)) {
            s_server_started = true;
            s_mcp_server.write_client_configs();
        }
        diag::log_tagged_fmt("init_chat", "mcp_server_start_done started=%d", s_server_started ? 1 : 0);
    }

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
    s_mcp_client_mgr.connect_all();
    s_mcp_clients_connected = true;
    diag::log_tagged("init_chat", "mcp_client_connect_all_done");

    diag::log_tagged("init_chat", "marketplace_load_installed_start");
    mcp_marketplace::load_installed(g_sa_settings.marketplace_installed_json);
    {
        auto installed = mcp_marketplace::get_installed();
        for (auto& srv : installed) {
            if (srv.enabled && srv.auto_connect)
                mcp_marketplace::activate_server(srv);
        }
    }
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

void shutdown_standalone_chat()
{
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
    if (s_server_started)
        s_mcp_server.stop();


    if (s_mcp_clients_connected) {
        s_mcp_client_mgr.disconnect_all();
        s_mcp_clients_connected = false;
    }


    g_sa_settings.marketplace_installed_json = mcp_marketplace::save_installed();
    mcp_marketplace::shutdown();

    persist_workspace_state();
    g_sa_settings.save();
    standalone_license::shutdown();
    g_sa_ai_client.reset();


    if (driver_bridge::using_kernel_driver())
        driver_bridge::unregister_dll_protection();

    s_initialized = false;
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
                size_t e = s;
                while (e < rest.size() && rest[e] != ' ' && rest[e] != '\t') ++e;
                cmd_args.push_back(rest.substr(s, e - s));
                s = e;
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
        auto* prof = g_sa_settings.get_active_profile();
        if (prof)
            ai.model_id = prof->display_name + " / " + prof->model;
        else
            ai.model_id = g_sa_settings.get_active_model();
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
        license::validated = false;
        license::check_failed = true;
        license::error_msg = standalone_license::last_error();
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


void chat_bind_session(const std::string& session_id)
{
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

    ImGui::PushStyleColor(ImGuiCol_PopupBg, IM_COL32(28, 28, 36, 245));
    ImGui::PushStyleColor(ImGuiCol_Border, IM_COL32(70, 70, 100, 180));
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
        ImGui::TextColored(ImVec4(1.f, 0.9f, 0.6f, 1.f), "  %s", name.c_str());
        ImGui::Spacing();

        if (!args_preview.empty()) {
            ImGui::Text("Arguments:");
            ImGui::PushStyleColor(ImGuiCol_ChildBg, IM_COL32(18, 18, 24, 200));
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

        ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(
            static_cast<int>(ax * 200), static_cast<int>(ay * 200), static_cast<int>(az * 200), 200));
        if (ImGui::Button("Allow", ImVec2(btn_w, 28))) {
            std::lock_guard<std::mutex> lk(s_tool_approval.mtx);
            s_tool_approval.approved = true;
            s_tool_approval.answered = true;
            s_tool_approval.cv.notify_one();
            ImGui::CloseCurrentPopup();
        }
        ImGui::PopStyleColor();

        ImGui::SameLine(0, 12.f);

        ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(120, 40, 40, 200));
        if (ImGui::Button("Deny", ImVec2(btn_w, 28))) {
            std::lock_guard<std::mutex> lk(s_tool_approval.mtx);
            s_tool_approval.approved = false;
            s_tool_approval.answered = true;
            s_tool_approval.cv.notify_one();
            ImGui::CloseCurrentPopup();
        }
        ImGui::PopStyleColor();

        ImGui::EndPopup();
    }
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);
}


void render_settings_inline(float panel_w, float panel_h)
{


    const float ax = globals::ui::accent.x, ay = globals::ui::accent.y, az = globals::ui::accent.z;
    const ImU32 accent_col   = IM_COL32(static_cast<int>(ax*255), static_cast<int>(ay*255), static_cast<int>(az*255), 255);
    const ImU32 accent_dim   = IM_COL32(static_cast<int>(ax*255), static_cast<int>(ay*255), static_cast<int>(az*255), 80);
    const ImU32 accent_glow  = IM_COL32(static_cast<int>(ax*255), static_cast<int>(ay*255), static_cast<int>(az*255), 40);
    const ImU32 text_primary = IM_COL32(225, 222, 240, 255);
    const ImU32 text_dim     = IM_COL32(160, 158, 175, 200);

    ImGui::PushStyleColor(ImGuiCol_FrameBg,         ImVec4(0.10f, 0.10f, 0.14f, 1.f));
    ImGui::PushStyleColor(ImGuiCol_FrameBgHovered,  ImVec4(0.14f, 0.14f, 0.19f, 1.f));
    ImGui::PushStyleColor(ImGuiCol_FrameBgActive,   ImVec4(0.16f, 0.16f, 0.22f, 1.f));
    ImGui::PushStyleColor(ImGuiCol_Button,          ImVec4(ax * 0.35f, ay * 0.35f, az * 0.35f, 0.6f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered,   ImVec4(ax * 0.5f, ay * 0.5f, az * 0.5f, 0.8f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,    ImVec4(ax * 0.6f, ay * 0.6f, az * 0.6f, 1.f));
    ImGui::PushStyleColor(ImGuiCol_Header,          ImVec4(ax * 0.25f, ay * 0.25f, az * 0.25f, 0.35f));
    ImGui::PushStyleColor(ImGuiCol_HeaderHovered,   ImVec4(ax * 0.35f, ay * 0.35f, az * 0.35f, 0.55f));
    ImGui::PushStyleColor(ImGuiCol_HeaderActive,    ImVec4(ax * 0.45f, ay * 0.45f, az * 0.45f, 0.75f));
    ImGui::PushStyleColor(ImGuiCol_SliderGrab,      ImVec4(ax, ay, az, 0.8f));
    ImGui::PushStyleColor(ImGuiCol_SliderGrabActive,ImVec4(ax, ay, az, 1.f));
    ImGui::PushStyleColor(ImGuiCol_CheckMark,       ImVec4(ax, ay, az, 1.f));
    ImGui::PushStyleColor(ImGuiCol_Tab,             ImVec4(0.f, 0.f, 0.f, 0.f));
    ImGui::PushStyleColor(ImGuiCol_TabHovered,      ImVec4(ax * 0.3f, ay * 0.3f, az * 0.3f, 0.4f));
    ImGui::PushStyleColor(ImGuiCol_TabSelected,     ImVec4(ax * 0.2f, ay * 0.2f, az * 0.2f, 0.6f));

    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding,  6.f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,   ImVec2(8.f, 5.f));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,    ImVec2(6.f, 5.f));

    {

        static bool  s_first = true;
        static float s_tab_anim = 0.f;
        static int   s_active_tab = 0;
        static float s_profile_sel_anim = 0.f;
        static int   s_profile_sel_target = 0;


        static int   s_selected_profile = 0;
        static char  s_name[128] = {};
        static char  s_base_url[512] = {};
        static char  s_api_key[512] = {};
        static char  s_model[256] = {};
        static char  s_headers[1024] = "{}";
        static bool  s_enabled = true;
        static int   s_kind = 0;
        static float s_temperature = 0.7f;
        static int   s_mcp_port = 29117;
        static bool  s_mcp_enabled = true;
        static int   s_sandbox_timeout = 30000;
        static int   s_sandbox_memory = 256;
        static int   s_sandbox_network = 0;


        static char  s_aws_access[256] = {};
        static char  s_aws_secret[256] = {};
        static char  s_aws_session[256] = {};
        static char  s_aws_region[64] = "us-east-1";
        static bool  s_aws_cross_region = false;
        static char  s_vertex_project[256] = {};
        static char  s_vertex_region[64] = "us-east5";
        static char  s_vertex_keyfile[512] = {};
        static int   s_ollama_num_ctx = 0;
        static int   s_reasoning_effort_idx = -1;
        static bool  s_lmstudio_spec = false;
        static char  s_lmstudio_draft[256] = {};
        static char  s_mistral_codestral[512] = {};
        static char  s_azure_deployment[256] = {};
        static char  s_azure_api_ver[64] = "2024-10-21";


        static bool s_enable_reasoning = false;
        static int  s_reasoning_budget = 10000;
        static char s_reasoning_effort[32] = "medium";
        static bool s_prompt_caching = true;
        static int  s_max_rounds = 15;
        static bool s_ai_features_init = false;


        static int   s_ed_tab_size = 4;
        static float s_ed_font_size = 14.0f;
        static bool  s_ed_line_numbers = true;
        static bool  s_ed_word_wrap = false;
        static bool  s_ed_minimap = false;
        static bool  s_ed_bracket_match = true;
        static bool  s_ed_highlight_line = true;
        static bool  s_ed_autocomplete = true;
        static bool  s_ed_ghost_text = false;
        static bool  s_ed_init = false;

        const float dt = ImGui::GetIO().DeltaTime;

        auto refresh_profile_buffers = [&]() {
            g_sa_settings.ensure_default_profiles();
            if (s_selected_profile < 0 || s_selected_profile >= static_cast<int>(g_sa_settings.provider_profiles.size()))
                s_selected_profile = 0;
            auto& profile = g_sa_settings.provider_profiles[s_selected_profile];
            snprintf(s_name, sizeof(s_name), "%s", profile.display_name.c_str());
            snprintf(s_base_url, sizeof(s_base_url), "%s", profile.base_url.c_str());
            snprintf(s_api_key, sizeof(s_api_key), "%s", profile.api_key.c_str());
            snprintf(s_model, sizeof(s_model), "%s", profile.model.c_str());
            snprintf(s_headers, sizeof(s_headers), "%s",
                     (profile.headers_json.empty() ? std::string("{}") : profile.headers_json).c_str());
            s_enabled = profile.enabled;

            const auto& kinds = settings_sa_t::provider_kinds();
            s_kind = 0;
            for (int i = 0; i < static_cast<int>(kinds.size()); ++i) {
                if (kinds[i] == sa_settings_detail::normalize_provider_kind(profile.kind)) {
                    s_kind = i;
                    break;
                }
            }


            snprintf(s_aws_access,  sizeof(s_aws_access),  "%s", profile.aws_access_key.c_str());
            snprintf(s_aws_secret,  sizeof(s_aws_secret),  "%s", profile.aws_secret_key.c_str());
            snprintf(s_aws_session, sizeof(s_aws_session), "%s", profile.aws_session_token.c_str());
            snprintf(s_aws_region,  sizeof(s_aws_region),  "%s", profile.aws_region.c_str());
            s_aws_cross_region = profile.aws_use_cross_region;
            snprintf(s_vertex_project, sizeof(s_vertex_project), "%s", profile.vertex_project_id.c_str());
            snprintf(s_vertex_region,  sizeof(s_vertex_region),  "%s", profile.vertex_region.c_str());
            snprintf(s_vertex_keyfile, sizeof(s_vertex_keyfile), "%s", profile.vertex_key_file.c_str());
            s_ollama_num_ctx = profile.ollama_num_ctx;
            s_reasoning_effort_idx = -1;
            if (profile.reasoning_effort == "low")    s_reasoning_effort_idx = 0;
            if (profile.reasoning_effort == "medium") s_reasoning_effort_idx = 1;
            if (profile.reasoning_effort == "high")   s_reasoning_effort_idx = 2;
            s_lmstudio_spec = profile.lmstudio_speculative_decoding;
            snprintf(s_lmstudio_draft,     sizeof(s_lmstudio_draft),     "%s", profile.lmstudio_draft_model.c_str());
            snprintf(s_mistral_codestral,  sizeof(s_mistral_codestral),  "%s", profile.mistral_codestral_url.c_str());
            snprintf(s_azure_deployment,   sizeof(s_azure_deployment),   "%s", profile.azure_deployment.c_str());
            snprintf(s_azure_api_ver,      sizeof(s_azure_api_ver),      "%s", profile.azure_api_version.c_str());

            s_profile_sel_target = s_selected_profile;
        };

        if (s_first) {
            s_first = false;
            g_sa_settings.ensure_default_profiles();
            for (int i = 0; i < static_cast<int>(g_sa_settings.provider_profiles.size()); ++i) {
                if (g_sa_settings.provider_profiles[i].id == g_sa_settings.active_provider_profile_id) {
                    s_selected_profile = i;
                    break;
                }
            }
            refresh_profile_buffers();
            s_temperature = static_cast<float>(g_sa_settings.temperature);
            s_mcp_port = g_sa_settings.mcp_port;
            s_mcp_enabled = g_sa_settings.mcp_enabled;
            s_sandbox_timeout = g_sa_settings.sandbox.timeout_ms;
            s_sandbox_memory = g_sa_settings.sandbox.memory_limit_mb;
            s_sandbox_network = g_sa_settings.sandbox.network_mode == "default" ? 1 : 0;
            s_tab_anim = 0.f;
            s_profile_sel_anim = static_cast<float>(s_selected_profile);


            s_enable_reasoning = g_sa_settings.enable_reasoning;
            s_reasoning_budget = g_sa_settings.reasoning_budget;
            snprintf(s_reasoning_effort, sizeof(s_reasoning_effort), "%s", g_sa_settings.reasoning_effort.c_str());
            s_prompt_caching = g_sa_settings.prompt_caching;
            s_max_rounds = g_sa_settings.max_agentic_rounds;
            s_ai_features_init = true;


            s_ed_tab_size = editor_config::tab_size;
            s_ed_font_size = editor_config::font_size;
            s_ed_line_numbers = editor_config::show_line_numbers;
            s_ed_word_wrap = editor_config::word_wrap;
            s_ed_minimap = editor_config::minimap;
            s_ed_bracket_match = editor_config::bracket_match;
            s_ed_highlight_line = editor_config::highlight_current_line;
            s_ed_autocomplete = editor_config::auto_complete;
            s_ed_ghost_text = g_sa_settings.ghost_text_enabled;
            s_ed_init = true;
        }


        s_tab_anim += (static_cast<float>(s_active_tab) - s_tab_anim) * (std::min)(dt * 12.f, 1.f);
        s_profile_sel_anim += (static_cast<float>(s_profile_sel_target) - s_profile_sel_anim) * (std::min)(dt * 14.f, 1.f);

        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 wp = ImGui::GetWindowPos();
        ImVec2 ws = ImGui::GetWindowSize();


        {
            dl->AddRectFilled(wp, ImVec2(wp.x + ws.x, wp.y + 38.f),
                IM_COL32(14, 14, 20, 255));
            dl->AddLine(ImVec2(wp.x, wp.y + 38.f), ImVec2(wp.x + ws.x, wp.y + 38.f),
                IM_COL32(255, 255, 255, 15));


            ImGui::SetCursorPos(ImVec2(8.f, 7.f));
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0,0,0,0));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(ax, ay, az, 0.15f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(ax, ay, az, 0.25f));
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(ax, ay, az, 0.9f));
            if (ImGui::Button("<##settings_back", ImVec2(24.f, 24.f))) {
                s_first = true;
                g_settings_open = false;
            }
            ImGui::PopStyleColor(4);
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Back to chat");

            ImGui::SameLine();
            const char* title = "Settings";
            ImVec2 tts = ImGui::CalcTextSize(title);
            ImGui::SetCursorPosY((38.f - tts.y) * 0.5f);
            dl->AddText(ImGui::GetCursorScreenPos(), text_primary, title);
        }

        ImGui::SetCursorPos(ImVec2(6.f, 42.f));


        {
            ImGui::SetNextItemWidth(ws.x - 12.f);
            g_sa_settings.ensure_default_profiles();
            if (s_selected_profile < 0 || s_selected_profile >= static_cast<int>(g_sa_settings.provider_profiles.size()))
                s_selected_profile = 0;
            const std::string& preview_name = g_sa_settings.provider_profiles[s_selected_profile].display_name;
            if (ImGui::BeginCombo("##profile_select", preview_name.c_str())) {
                for (int i = 0; i < static_cast<int>(g_sa_settings.provider_profiles.size()); ++i) {
                    ImGui::PushID(i);
                    auto& prof = g_sa_settings.provider_profiles[i];
                    ImU32 dot_col = prof.enabled ?
                        IM_COL32(80, 220, 120, 255) : IM_COL32(100, 100, 100, 120);
                    ImVec2 cpos = ImGui::GetCursorScreenPos();
                    dl->AddCircleFilled(ImVec2(cpos.x + 6.f, cpos.y + ImGui::GetFrameHeight() * 0.5f), 3.f, dot_col);
                    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 14.f);
                    if (ImGui::Selectable(prof.display_name.c_str(), i == s_selected_profile)) {
                        s_selected_profile = i;
                        refresh_profile_buffers();
                    }
                    ImGui::PopID();
                }
                ImGui::EndCombo();
            }

            float half_w = (ws.x - 18.f) * 0.5f;
            ImGui::SetCursorPosX(6.f);
            if (ImGui::Button("+ Add##prof_add", ImVec2(half_w, 26.f))) {
                provider_profile_t profile;
                profile.display_name = "New Profile";
                profile.id = sa_settings_detail::make_profile_id(profile.display_name, g_sa_settings.provider_profiles.size() + 1);
                profile.kind = "openai_compatible";
                profile.base_url = "https://api.openai.com";
                profile.model = "gpt-4.1-mini";
                g_sa_settings.provider_profiles.push_back(std::move(profile));
                s_selected_profile = static_cast<int>(g_sa_settings.provider_profiles.size()) - 1;
                refresh_profile_buffers();
            }
            ImGui::SameLine(0, 6.f);
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.3f, 0.12f, 0.12f, 0.6f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.5f, 0.15f, 0.15f, 0.8f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.6f, 0.2f, 0.2f, 1.f));
            if (ImGui::Button("- Remove##prof_rm", ImVec2(half_w, 26.f)) &&
                g_sa_settings.provider_profiles.size() > 1) {
                g_sa_settings.provider_profiles.erase(g_sa_settings.provider_profiles.begin() + s_selected_profile);
                s_selected_profile = (s_selected_profile > 0) ? (s_selected_profile - 1) : 0;
                refresh_profile_buffers();
            }
            ImGui::PopStyleColor(3);
        }

        ImGui::Dummy(ImVec2(0, 2));

        const float content_h = panel_h - ImGui::GetCursorPosY() - 44.f;


        ImGui::BeginChild("##settings_right_area", ImVec2(ws.x - 4.f, content_h), false);
        {
            const float right_w = ws.x;


            const char* tab_labels[] = {"Provider", "AI", "Editor", "MCP", "Sandbox"};
            constexpr int tab_count = 5;
            float tab_positions[tab_count] = {};
            float tab_widths[tab_count] = {};

            ImGui::Dummy(ImVec2(0, 4));
            float tab_start_x = 4.f;
            ImVec2 tab_origin = ImGui::GetCursorScreenPos();
            tab_origin.x += tab_start_x;

            for (int t = 0; t < tab_count; ++t) {
                tab_positions[t] = tab_start_x;
                ImVec2 tsz = ImGui::CalcTextSize(tab_labels[t]);
                tab_widths[t] = tsz.x + 14.f;

                ImGui::SetCursorPosX(tab_positions[t]);
                ImGui::PushID(t + 100);
                bool is_active_tab = (t == s_active_tab);
                ImU32 tab_text_col = is_active_tab ? accent_col : text_dim;

                ImVec2 tp = ImGui::GetCursorScreenPos();
                if (ImGui::InvisibleButton("##tab", ImVec2(tab_widths[t], 26.f))) {
                    s_active_tab = t;
                }
                bool tab_hovered = ImGui::IsItemHovered();
                if (tab_hovered && !is_active_tab)
                    tab_text_col = text_primary;

                dl->AddText(ImVec2(tp.x + 7.f, tp.y + 4.f), tab_text_col, tab_labels[t]);
                ImGui::PopID();

                tab_start_x += tab_widths[t] + 2.f;
                if (t < tab_count - 1)
                    ImGui::SameLine(0, 2.f);
            }


            float ul_x = 0.f, ul_w = 0.f;
            {
                int from_tab = static_cast<int>(s_tab_anim);
                int to_tab = from_tab + 1;
                float frac = s_tab_anim - static_cast<float>(from_tab);
                if (from_tab < 0) from_tab = 0;
                if (to_tab >= tab_count) to_tab = tab_count - 1;
                if (from_tab >= tab_count) from_tab = tab_count - 1;

                float x0 = tab_positions[from_tab] + 7.f;
                float w0 = tab_widths[from_tab] - 14.f;
                float x1 = tab_positions[to_tab] + 7.f;
                float w1 = tab_widths[to_tab] - 14.f;
                ul_x = x0 + (x1 - x0) * frac;
                ul_w = w0 + (w1 - w0) * frac;
            }
            ImVec2 rp = ImGui::GetWindowPos();
            float underline_y = tab_origin.y + 26.f;
            dl->AddRectFilled(
                ImVec2(rp.x + ul_x, underline_y),
                ImVec2(rp.x + ul_x + ul_w, underline_y + 2.5f),
                accent_col, 1.5f);

            dl->AddRectFilled(
                ImVec2(rp.x + ul_x - 4.f, underline_y + 2.f),
                ImVec2(rp.x + ul_x + ul_w + 4.f, underline_y + 8.f),
                accent_glow, 4.f);


            ImGui::Dummy(ImVec2(0, 4));
            dl->AddLine(
                ImVec2(rp.x, underline_y + 10.f),
                ImVec2(rp.x + right_w, underline_y + 10.f),
                IM_COL32(255, 255, 255, 8));

            ImGui::Dummy(ImVec2(0, 8));


            auto begin_card = [&](const char* label, float width = -1.f) {
                ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.f);
                ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.08f, 0.08f, 0.11f, 0.95f));
                ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(1.f, 1.f, 1.f, 0.06f));
                ImGui::BeginChild(label, ImVec2(width, 0.f), ImGuiChildFlags_AutoResizeY | ImGuiChildFlags_Borders);
                ImGui::Dummy(ImVec2(0, 6));
                ImGui::Indent(6.f);
            };
            auto end_card = [&]() {
                ImGui::Unindent(6.f);
                ImGui::Dummy(ImVec2(0, 6));
                ImGui::EndChild();
                ImGui::PopStyleColor(2);
                ImGui::PopStyleVar();
            };

            ImGui::BeginChild("##tab_content", ImVec2(0, 0), false);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(4.f, 4.f));
            ImGui::Indent(2.f);


            auto section_header = [&](const char* text) {
                ImVec4 acc_vec(ax, ay, az, 1.f);
                ImGui::TextColored(acc_vec, "%s", text);
                ImVec2 p = ImGui::GetCursorScreenPos();
                ImVec2 tsz = ImGui::CalcTextSize(text);
                ImDrawList* wdl = ImGui::GetWindowDrawList();
                wdl->AddLine(ImVec2(p.x, p.y - 2.f), ImVec2(p.x + tsz.x, p.y - 2.f),
                             accent_dim, 2.f);
                ImGui::Dummy(ImVec2(0, 2.f));
            };

            const auto& kinds = settings_sa_t::provider_kinds();
            const std::string current_kind = kinds[s_kind];


            if (s_active_tab == 0)
            {
                begin_card("##profile_card");
                {
                    section_header("Profile");

                    ImGui::Text("Name");
                    ImGui::SetNextItemWidth(-14.f);
                    ImGui::InputText("##profile_name", s_name, sizeof(s_name));

                    ImGui::Text("Provider");
                    ImGui::SetNextItemWidth(-14.f);
                    {

                        const std::string preview = settings_sa_t::provider_display_name(kinds[s_kind]);
                        if (ImGui::BeginCombo("##provider_kind", preview.c_str())) {
                            for (int i = 0; i < static_cast<int>(kinds.size()); ++i) {
                                const bool sel = (i == s_kind);
                                const std::string& disp = settings_sa_t::provider_display_name(kinds[i]);
                                if (ImGui::Selectable(disp.c_str(), sel)) {
                                    s_kind = i;

                                    const auto& new_kind = kinds[s_kind];
                                    provider_profile_t tmp;
                                    tmp.kind = new_kind;
                                    const auto& default_models = settings_sa_t::models_for_kind(new_kind);
                                    if (!default_models.empty())
                                        snprintf(s_model, sizeof(s_model), "%s", default_models[0].c_str());

                                    s_base_url[0] = '\0';
                                }
                                if (sel) ImGui::SetItemDefaultFocus();
                            }
                            ImGui::EndCombo();
                        }
                    }

                    ImGui::Checkbox("Enabled", &s_enabled);
                }
                end_card();

                ImGui::Dummy(ImVec2(0, 4));

                begin_card("##model_card");
                {
                    section_header("Model Configuration");

                    ImGui::Text("Model");
                    ImGui::SetNextItemWidth(-14.f);
                    ImGui::InputText("##profile_model", s_model, sizeof(s_model));

                    const auto& presets = settings_sa_t::models_for_kind(current_kind);
                    if (!presets.empty()) {
                        ImGui::SetNextItemWidth(-14.f);
                        if (ImGui::BeginCombo("##model_presets", "Select from presets...")) {
                            for (const auto& preset : presets) {
                                bool is_current = (std::string(s_model) == preset);
                                if (ImGui::Selectable(preset.c_str(), is_current)) {
                                    snprintf(s_model, sizeof(s_model), "%s", preset.c_str());
                                }
                                if (is_current) ImGui::SetItemDefaultFocus();
                            }
                            ImGui::EndCombo();
                        }
                    }

                    ImGui::Text("Temperature");
                    ImGui::SetNextItemWidth(-14.f);
                    ImGui::SliderFloat("##temp", &s_temperature, 0.0f, 2.0f, "%.2f");
                }
                end_card();

                ImGui::Dummy(ImVec2(0, 4));

                begin_card("##auth_card");
                {
                    section_header("Authentication");

                    if (current_kind == "bedrock") {
                        ImGui::Text("AWS Access Key");
                        ImGui::SetNextItemWidth(-14.f);
                        ImGui::InputText("##aws_access", s_aws_access, sizeof(s_aws_access), ImGuiInputTextFlags_Password);
                        ImGui::Text("AWS Secret Key");
                        ImGui::SetNextItemWidth(-14.f);
                        ImGui::InputText("##aws_secret", s_aws_secret, sizeof(s_aws_secret), ImGuiInputTextFlags_Password);
                        ImGui::Text("Session Token (optional)");
                        ImGui::SetNextItemWidth(-14.f);
                        ImGui::InputText("##aws_session", s_aws_session, sizeof(s_aws_session), ImGuiInputTextFlags_Password);
                        ImGui::Text("Region");
                        ImGui::SetNextItemWidth(-14.f);
                        ImGui::InputText("##aws_region", s_aws_region, sizeof(s_aws_region));
                        ImGui::Checkbox("Cross-Region Inference", &s_aws_cross_region);
                    } else if (current_kind == "vertex") {
                        ImGui::Text("Project ID");
                        ImGui::SetNextItemWidth(-14.f);
                        ImGui::InputText("##vertex_project", s_vertex_project, sizeof(s_vertex_project));
                        ImGui::Text("Region");
                        ImGui::SetNextItemWidth(-14.f);
                        ImGui::InputText("##vertex_region", s_vertex_region, sizeof(s_vertex_region));
                        ImGui::Text("Service Account Key File");
                        ImGui::SetNextItemWidth(-14.f);
                        ImGui::InputText("##vertex_keyfile", s_vertex_keyfile, sizeof(s_vertex_keyfile));
                        if (ImGui::IsItemHovered())
                            ImGui::SetTooltip("Path to GCP service account JSON key file");
                    } else if (current_kind == "ollama" || current_kind == "lmstudio"
                               || current_kind == "local" || current_kind == "qwen_code") {
                        ImGui::TextColored(ImVec4(0.6f, 0.8f, 0.6f, 0.9f),
                            "Local/free provider - no API key required");
                        ImGui::Text("API Key (optional)");
                        ImGui::SetNextItemWidth(-14.f);
                        ImGui::InputText("##profile_api_key", s_api_key, sizeof(s_api_key), ImGuiInputTextFlags_Password);
                    } else {
                        ImGui::Text("API Key");
                        ImGui::SetNextItemWidth(-14.f);
                        ImGui::InputText("##profile_api_key", s_api_key, sizeof(s_api_key), ImGuiInputTextFlags_Password);
                    }
                }
                end_card();

                ImGui::Dummy(ImVec2(0, 4));

                begin_card("##endpoint_card");
                {
                    section_header("Endpoint");

                    ImGui::Text("Base URL (leave empty for default)");
                    ImGui::SetNextItemWidth(-14.f);
                    ImGui::InputText("##profile_base_url", s_base_url, sizeof(s_base_url));
                    if (ImGui::IsItemHovered()) {
                        provider_profile_t tmp;
                        tmp.kind = current_kind;
                        std::string def_url;
                        if (current_kind == "gemini")           def_url = "https://generativelanguage.googleapis.com";
                        else if (current_kind == "anthropic")   def_url = "https://api.anthropic.com";
                        else if (current_kind == "openrouter")  def_url = "https://openrouter.ai";
                        else if (current_kind == "deepseek")    def_url = "https://api.deepseek.com";
                        else if (current_kind == "mistral")     def_url = "https://api.mistral.ai";
                        else if (current_kind == "xai")         def_url = "https://api.x.ai";
                        else if (current_kind == "sambanova")   def_url = "https://api.sambanova.ai";
                        else if (current_kind == "fireworks")   def_url = "https://api.fireworks.ai";
                        else if (current_kind == "moonshot")    def_url = "https://api.moonshot.cn";
                        else if (current_kind == "minimax")     def_url = "https://api.minimaxi.chat";
                        else if (current_kind == "qwen_code")   def_url = "https://chat.qwen.ai";
                        else if (current_kind == "baseten")     def_url = "https://bridge.baseten.co";
                        else if (current_kind == "zai")         def_url = "https://open.bigmodel.cn";
                        else if (current_kind == "openai_codex") def_url = "https://api.openai.com";
                        else if (current_kind == "ollama")      def_url = "http://127.0.0.1:11434";
                        else if (current_kind == "lmstudio")    def_url = "http://127.0.0.1:1234";
                        else if (current_kind == "requesty")    def_url = "https://router.requesty.ai";
                        else if (current_kind == "unbound")     def_url = "https://api.getunbound.ai";
                        else if (current_kind == "vercel_ai")   def_url = "https://sdk.vercel.ai";
                        else if (current_kind == "litellm")     def_url = "http://127.0.0.1:4000";
                        else                                    def_url = "https://api.openai.com";
                        ImGui::SetTooltip("Default: %s", def_url.c_str());
                    }

                    ImGui::Text("Custom Headers (JSON)");
                    ImGui::SetNextItemWidth(-14.f);
                    ImGui::InputTextMultiline("##profile_headers", s_headers, sizeof(s_headers), ImVec2(-14.f, 70.f));


                    if (current_kind == "ollama") {
                        ImGui::Text("Context Window (0 = default)");
                        ImGui::SetNextItemWidth(-14.f);
                        ImGui::InputInt("##ollama_ctx", &s_ollama_num_ctx, 1024, 4096);
                        s_ollama_num_ctx = (std::max)(s_ollama_num_ctx, 0);
                    }
                    if (current_kind == "openai_native" || current_kind == "openai_compatible"
                        || current_kind == "openai_codex") {
                        ImGui::Text("Reasoning Effort (o-series models)");
                        ImGui::SetNextItemWidth(-14.f);
                        const char* r_labels[] = {"(none)", "Low", "Medium", "High"};
                        ImGui::Combo("##reasoning_effort", &s_reasoning_effort_idx, r_labels, 4);
                    }
                    if (current_kind == "lmstudio") {
                        ImGui::Checkbox("Speculative Decoding", &s_lmstudio_spec);
                        if (s_lmstudio_spec) {
                            ImGui::Text("Draft Model");
                            ImGui::SetNextItemWidth(-14.f);
                            ImGui::InputText("##lmstudio_draft", s_lmstudio_draft, sizeof(s_lmstudio_draft));
                        }
                    }
                    if (current_kind == "mistral") {
                        ImGui::Text("Codestral URL (optional)");
                        ImGui::SetNextItemWidth(-14.f);
                        ImGui::InputText("##mistral_codestral", s_mistral_codestral, sizeof(s_mistral_codestral));
                    }
                }
                end_card();
            }


            else if (s_active_tab == 1)
            {
                if (!s_ai_features_init) {
                    s_enable_reasoning = g_sa_settings.enable_reasoning;
                    s_reasoning_budget = g_sa_settings.reasoning_budget;
                    snprintf(s_reasoning_effort, sizeof(s_reasoning_effort), "%s", g_sa_settings.reasoning_effort.c_str());
                    s_prompt_caching = g_sa_settings.prompt_caching;
                    s_max_rounds = g_sa_settings.max_agentic_rounds;
                    s_ai_features_init = true;
                }

                begin_card("##reasoning_card");
                {
                    section_header("Reasoning");

                    ImGui::Checkbox("Enable Reasoning", &s_enable_reasoning);
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Enable extended reasoning / thinking for models that support it");
                    if (s_enable_reasoning) {
                        ImGui::Text("Reasoning Budget (tokens)");
                        ImGui::SetNextItemWidth(-14.f);
                        ImGui::InputInt("##reasoning_budget", &s_reasoning_budget, 1000, 5000);
                        s_reasoning_budget = (std::max)(s_reasoning_budget, 1024);
                    }

                    ImGui::Text("Reasoning Effort");
                    ImGui::SetNextItemWidth(-14.f);
                    static const char* effort_labels[] = {
                        "minimal", "low", "medium", "high", "xhigh"
                    };
                    int effort_idx = 2;
                    for (int i = 0; i < 5; ++i) {
                        if (std::string(effort_labels[i]) == s_reasoning_effort) { effort_idx = i; break; }
                    }
                    if (ImGui::Combo("##reasoning_effort", &effort_idx, effort_labels, 5)) {
                        snprintf(s_reasoning_effort, sizeof(s_reasoning_effort), "%s", effort_labels[effort_idx]);
                    }
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Controls how much effort the model puts into reasoning (provider-agnostic)");
                }
                end_card();

                ImGui::Dummy(ImVec2(0, 4));

                begin_card("##caching_card");
                {
                    section_header("Caching");

                    ImGui::Checkbox("Prompt Caching", &s_prompt_caching);
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Cache system prompts to reduce cost and latency (when supported)");
                }
                end_card();

                ImGui::Dummy(ImVec2(0, 4));

                begin_card("##agentic_card");
                {
                    section_header("Agentic");

                    ImGui::Text("Max Agentic Rounds");
                    ImGui::SetNextItemWidth(-14.f);
                    ImGui::SliderInt("##max_rounds", &s_max_rounds, 1, 50);
                }
                end_card();

                ImGui::Dummy(ImVec2(0, 4));


                begin_card("##auto_approval_card");
                {
                    section_header("Auto-Approval");

                    static bool s_aa_read = false, s_aa_write = false, s_aa_exec = false;
                    static bool s_aa_mcp = false, s_aa_mode = false, s_aa_subtask = false;
                    static int  s_aa_max_req = 0;
                    static float s_aa_max_cost = 0.0f;
                    static char s_aa_cmds[512] = {};
                    static bool s_aa_init = false;

                    if (!s_aa_init) {
                        s_aa_read    = g_sa_settings.auto_approve_read;
                        s_aa_write   = g_sa_settings.auto_approve_write;
                        s_aa_exec    = g_sa_settings.auto_approve_execute;
                        s_aa_mcp     = g_sa_settings.auto_approve_mcp;
                        s_aa_mode    = g_sa_settings.auto_approve_mode_switch;
                        s_aa_subtask = g_sa_settings.auto_approve_subtask;
                        s_aa_max_req = g_sa_settings.auto_approve_max_requests;
                        s_aa_max_cost = static_cast<float>(g_sa_settings.auto_approve_max_cost);
                        snprintf(s_aa_cmds, sizeof(s_aa_cmds), "%s",
                                 g_sa_settings.auto_approve_allowed_commands.c_str());
                        s_aa_init = true;
                    }

                    ImGui::Checkbox("Read Operations", &s_aa_read);
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Auto-approve: read_file, list_directory, search_files, etc.");

                    ImGui::Checkbox("Write Operations", &s_aa_write);
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Auto-approve: write_file, edit_file, create_file, etc.");

                    ImGui::Checkbox("Command Execution", &s_aa_exec);
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Auto-approve: execute_command (respects allowed commands list)");

                    ImGui::Checkbox("MCP Tools", &s_aa_mcp);
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Auto-approve: remote MCP server tool calls");

                    ImGui::Checkbox("Agent Switching", &s_aa_mode);
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Auto-approve: switch_agent, task");

                    ImGui::Checkbox("Subtask Spawning", &s_aa_subtask);

                    ImGui::Spacing();
                    ImGui::Text("Max Requests per Task");
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("0 = unlimited");
                    ImGui::SetNextItemWidth(-14.f);
                    ImGui::SliderInt("##aa_max_req", &s_aa_max_req, 0, 200);

                    ImGui::Text("Max Cost per Task ($)");
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("0 = unlimited");
                    ImGui::SetNextItemWidth(-14.f);
                    ImGui::SliderFloat("##aa_max_cost", &s_aa_max_cost, 0.0f, 50.0f, "$%.2f");

                    ImGui::Text("Allowed Command Prefixes");
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Comma-separated prefixes for execute_command auto-approval\ne.g.: npm test, cargo build, python");
                    ImGui::SetNextItemWidth(-14.f);
                    ImGui::InputText("##aa_cmds", s_aa_cmds, sizeof(s_aa_cmds));


                    g_sa_settings.auto_approve_read    = s_aa_read;
                    g_sa_settings.auto_approve_write   = s_aa_write;
                    g_sa_settings.auto_approve_execute  = s_aa_exec;
                    g_sa_settings.auto_approve_mcp     = s_aa_mcp;
                    g_sa_settings.auto_approve_mode_switch = s_aa_mode;
                    g_sa_settings.auto_approve_subtask = s_aa_subtask;
                    g_sa_settings.auto_approve_max_requests = s_aa_max_req;
                    g_sa_settings.auto_approve_max_cost = static_cast<double>(s_aa_max_cost);
                    g_sa_settings.auto_approve_allowed_commands = s_aa_cmds;
                }
                end_card();

                ImGui::Dummy(ImVec2(0, 4));


                begin_card("##condensation_card");
                {
                    section_header("Context Management");

                    static float s_condense_thresh = 0.80f;
                    static float s_condense_buffer = 0.10f;
                    static bool  s_cond_init = false;
                    if (!s_cond_init) {
                        s_condense_thresh = static_cast<float>(g_sa_settings.condense_threshold);
                        s_condense_buffer = static_cast<float>(g_sa_settings.condense_buffer);
                        s_cond_init = true;
                    }

                    ImGui::Text("Condense Threshold");
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Fraction of context window used before auto-condensing (0.0-1.0)");
                    ImGui::SetNextItemWidth(-14.f);
                    ImGui::SliderFloat("##condense_thresh", &s_condense_thresh, 0.5f, 0.95f, "%.0f%%");

                    ImGui::Text("Response Buffer");
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Fraction reserved for model response tokens");
                    ImGui::SetNextItemWidth(-14.f);
                    ImGui::SliderFloat("##condense_buffer", &s_condense_buffer, 0.05f, 0.30f, "%.0f%%");

                    g_sa_settings.condense_threshold = static_cast<double>(s_condense_thresh);
                    g_sa_settings.condense_buffer = static_cast<double>(s_condense_buffer);
                }
                end_card();
            }


            else if (s_active_tab == 2)
            {
                if (!s_ed_init) {
                    s_ed_tab_size = editor_config::tab_size;
                    s_ed_font_size = editor_config::font_size;
                    s_ed_line_numbers = editor_config::show_line_numbers;
                    s_ed_word_wrap = editor_config::word_wrap;
                    s_ed_minimap = editor_config::minimap;
                    s_ed_bracket_match = editor_config::bracket_match;
                    s_ed_highlight_line = editor_config::highlight_current_line;
                    s_ed_autocomplete = editor_config::auto_complete;
                    s_ed_ghost_text = g_sa_settings.ghost_text_enabled;
                    s_ed_init = true;
                }

                begin_card("##editor_layout_card");
                {
                    section_header("Layout");

                    ImGui::Text("Tab Size");
                    ImGui::SetNextItemWidth(-14.f);
                    ImGui::SliderInt("##ed_tab_size", &s_ed_tab_size, 1, 8);

                    ImGui::Text("Font Size");
                    ImGui::SetNextItemWidth(-14.f);
                    ImGui::SliderFloat("##ed_font_size", &s_ed_font_size, 8.0f, 32.0f, "%.0f");

                    ImGui::Checkbox("Show Line Numbers", &s_ed_line_numbers);
                    ImGui::Checkbox("Word Wrap", &s_ed_word_wrap);
                    ImGui::Checkbox("Minimap", &s_ed_minimap);
                }
                end_card();

                ImGui::Dummy(ImVec2(0, 4));

                begin_card("##editor_features_card");
                {
                    section_header("Features");

                    ImGui::Checkbox("Highlight Current Line", &s_ed_highlight_line);
                    ImGui::Checkbox("Bracket Matching", &s_ed_bracket_match);
                    ImGui::Checkbox("Auto-Complete", &s_ed_autocomplete);
                    ImGui::Checkbox("Ghost Text (AI Suggestions)", &s_ed_ghost_text);
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("AI-generated completions as translucent text (Tab to accept)");
                }
                end_card();
            }


            else if (s_active_tab == 3)
            {
                begin_card("##mcp_server_card");
                {
                    section_header("Built-in MCP Server");

                    ImGui::Checkbox("Enable MCP Server", &s_mcp_enabled);
                    if (s_mcp_enabled) {
                        ImGui::SameLine();
                        ImGui::SetNextItemWidth(90.f);
                        ImGui::InputInt("Port", &s_mcp_port, 0, 0);
                    }
                }
                end_card();

                ImGui::Dummy(ImVec2(0, 4));

                begin_card("##mcp_clients_card");
                {
                    section_header("External MCP Servers");

                    static int s_mcp_client_sel = 0;
                    static char s_mcp_cl_name[128] = {};
                    static char s_mcp_cl_url[512] = {};
                    static char s_mcp_cl_key[512] = {};
                    static char s_mcp_cl_cmd[512] = {};
                    static char s_mcp_cl_args[512] = {};
                    static int  s_mcp_cl_transport = 0;
                    static bool s_mcp_cl_enabled = true;
                    static bool s_mcp_cl_auto = true;

                    auto refresh_mcp_cl = [&]() {
                        if (s_mcp_client_sel >= 0 && s_mcp_client_sel < static_cast<int>(g_sa_settings.mcp_client_servers.size())) {
                            auto& srv = g_sa_settings.mcp_client_servers[s_mcp_client_sel];
                            snprintf(s_mcp_cl_name, sizeof(s_mcp_cl_name), "%s", srv.name.c_str());
                            snprintf(s_mcp_cl_url,  sizeof(s_mcp_cl_url),  "%s", srv.url.c_str());
                            snprintf(s_mcp_cl_key,  sizeof(s_mcp_cl_key),  "%s", srv.api_key.c_str());
                            snprintf(s_mcp_cl_cmd,  sizeof(s_mcp_cl_cmd),  "%s", srv.command.c_str());
                            snprintf(s_mcp_cl_args, sizeof(s_mcp_cl_args), "%s", srv.args.c_str());
                            s_mcp_cl_transport = (srv.transport == "stdio") ? 1 : 0;
                            s_mcp_cl_enabled = srv.enabled;
                            s_mcp_cl_auto = srv.auto_connect;
                        } else {
                            memset(s_mcp_cl_name, 0, sizeof(s_mcp_cl_name));
                            memset(s_mcp_cl_url,  0, sizeof(s_mcp_cl_url));
                            memset(s_mcp_cl_key,  0, sizeof(s_mcp_cl_key));
                            memset(s_mcp_cl_cmd,  0, sizeof(s_mcp_cl_cmd));
                            memset(s_mcp_cl_args, 0, sizeof(s_mcp_cl_args));
                            s_mcp_cl_transport = 0;
                            s_mcp_cl_enabled = true;
                            s_mcp_cl_auto = true;
                        }
                    };

                    auto statuses = s_mcp_client_mgr.get_status();
                    for (int i = 0; i < static_cast<int>(g_sa_settings.mcp_client_servers.size()); ++i) {
                        ImVec4 indicator = ImVec4(0.5f, 0.5f, 0.5f, 1.f);
                        for (const auto& st : statuses) {
                            if (st.name == g_sa_settings.mcp_client_servers[i].name) {
                                switch (st.state) {
                                case mcp_client::connection_state_t::connected:    indicator = ImVec4(0.2f, 0.9f, 0.3f, 1.f); break;
                                case mcp_client::connection_state_t::connecting:
                                case mcp_client::connection_state_t::reconnecting: indicator = ImVec4(0.9f, 0.8f, 0.2f, 1.f); break;
                                case mcp_client::connection_state_t::error:        indicator = ImVec4(0.9f, 0.2f, 0.2f, 1.f); break;
                                default: break;
                                }
                                break;
                            }
                        }
                        ImGui::PushStyleColor(ImGuiCol_Text, indicator);
                        ImGui::Bullet();
                        ImGui::PopStyleColor();
                        ImGui::SameLine();
                        if (ImGui::Selectable(g_sa_settings.mcp_client_servers[i].name.c_str(),
                                              i == s_mcp_client_sel)) {
                            s_mcp_client_sel = i;
                            refresh_mcp_cl();
                        }
                    }

                    ImGui::Dummy(ImVec2(0, 4));
                    if (ImGui::SmallButton("+ Add Server")) {
                        mcp_client_server_t srv;
                        srv.name = "New Server";
                        srv.url = "http://localhost:3001";
                        g_sa_settings.mcp_client_servers.push_back(srv);
                        s_mcp_client_sel = static_cast<int>(g_sa_settings.mcp_client_servers.size()) - 1;
                        refresh_mcp_cl();
                    }
                    ImGui::SameLine();
                    if (ImGui::SmallButton("- Remove") &&
                        s_mcp_client_sel >= 0 && s_mcp_client_sel < static_cast<int>(g_sa_settings.mcp_client_servers.size()))
                    {
                        g_sa_settings.mcp_client_servers.erase(
                            g_sa_settings.mcp_client_servers.begin() + s_mcp_client_sel);
                        if (s_mcp_client_sel > 0) --s_mcp_client_sel;
                        refresh_mcp_cl();
                    }

                    if (s_mcp_client_sel >= 0 && s_mcp_client_sel < static_cast<int>(g_sa_settings.mcp_client_servers.size())) {
                        ImGui::Separator();
                        ImGui::Text("Server Name"); ImGui::SetNextItemWidth(-14.f);
                        ImGui::InputText("##mcp_cl_name", s_mcp_cl_name, sizeof(s_mcp_cl_name));

                        const char* transports[] = {"HTTP/SSE", "Stdio"};
                        ImGui::Text("Transport"); ImGui::SetNextItemWidth(-14.f);
                        ImGui::Combo("##mcp_cl_transport", &s_mcp_cl_transport, transports, 2);

                        if (s_mcp_cl_transport == 0) {
                            ImGui::Text("URL"); ImGui::SetNextItemWidth(-14.f);
                            ImGui::InputText("##mcp_cl_url", s_mcp_cl_url, sizeof(s_mcp_cl_url));
                            ImGui::Text("API Key"); ImGui::SetNextItemWidth(-14.f);
                            ImGui::InputText("##mcp_cl_key", s_mcp_cl_key, sizeof(s_mcp_cl_key), ImGuiInputTextFlags_Password);
                        } else {
                            ImGui::Text("Command"); ImGui::SetNextItemWidth(-14.f);
                            ImGui::InputText("##mcp_cl_cmd", s_mcp_cl_cmd, sizeof(s_mcp_cl_cmd));
                            ImGui::Text("Arguments"); ImGui::SetNextItemWidth(-14.f);
                            ImGui::InputText("##mcp_cl_args", s_mcp_cl_args, sizeof(s_mcp_cl_args));
                        }

                        ImGui::Checkbox("Enabled##mcp_cl", &s_mcp_cl_enabled);
                        ImGui::SameLine();
                        ImGui::Checkbox("Auto-Connect", &s_mcp_cl_auto);

                        auto& srv = g_sa_settings.mcp_client_servers[s_mcp_client_sel];
                        srv.name         = s_mcp_cl_name;
                        srv.url          = s_mcp_cl_url;
                        srv.api_key      = s_mcp_cl_key;
                        srv.command      = s_mcp_cl_cmd;
                        srv.args         = s_mcp_cl_args;
                        srv.transport    = (s_mcp_cl_transport == 1) ? "stdio" : "http_sse";
                        srv.enabled      = s_mcp_cl_enabled;
                        srv.auto_connect = s_mcp_cl_auto;
                    }
                }
                end_card();
            }


            else if (s_active_tab == 4)
            {
                begin_card("##sandbox_card");
                {
                    section_header("Sandbox Configuration");

                    ImGui::Text("Timeout (ms)");
                    ImGui::SetNextItemWidth(-14.f);
                    ImGui::InputInt("##sandbox_timeout", &s_sandbox_timeout, 0, 0);

                    ImGui::Text("Memory Budget (MB)");
                    ImGui::SetNextItemWidth(-14.f);
                    ImGui::InputInt("##sandbox_memory", &s_sandbox_memory, 0, 0);

                    const char* network_modes[] = {"Off", "Default"};
                    ImGui::Text("Network Access");
                    ImGui::SetNextItemWidth(-14.f);
                    ImGui::Combo("##sandbox_net", &s_sandbox_network, network_modes, IM_ARRAYSIZE(network_modes));
                }
                end_card();
            }

            ImGui::Unindent(2.f);
            ImGui::PopStyleVar();
            ImGui::EndChild();
        }
        ImGui::EndChild();


        {
            float bar_y = panel_h - 42.f;
            dl->AddRectFilled(ImVec2(wp.x, wp.y + bar_y), ImVec2(wp.x + ws.x, wp.y + panel_h),
                IM_COL32(14, 14, 20, 255));
            dl->AddLine(ImVec2(wp.x, wp.y + bar_y), ImVec2(wp.x + ws.x, wp.y + bar_y),
                IM_COL32(255, 255, 255, 15));

            float btn_w = (ws.x - 18.f) * 0.5f;
            ImGui::SetCursorPos(ImVec2(6.f, bar_y + 7.f));

            if (ImGui::Button("Save", ImVec2(btn_w, 28.f))) {
                if (s_selected_profile < 0 || s_selected_profile >= static_cast<int>(g_sa_settings.provider_profiles.size()))
                    s_selected_profile = 0;
                auto& profile = g_sa_settings.provider_profiles[s_selected_profile];
                profile.display_name = s_name[0] ? s_name : "Profile";
                const auto& ks = settings_sa_t::provider_kinds();
                profile.kind = ks[s_kind];
                profile.base_url = s_base_url;
                profile.api_key = s_api_key;
                profile.model = s_model;
                profile.headers_json = s_headers;
                profile.enabled = s_enabled;
                g_sa_settings.active_provider_profile_id = profile.id;

                profile.aws_access_key = s_aws_access;
                profile.aws_secret_key = s_aws_secret;
                profile.aws_session_token = s_aws_session;
                profile.aws_region = s_aws_region;
                profile.aws_use_cross_region = s_aws_cross_region;
                profile.vertex_project_id = s_vertex_project;
                profile.vertex_region = s_vertex_region;
                profile.vertex_key_file = s_vertex_keyfile;
                profile.ollama_num_ctx = s_ollama_num_ctx;
                static const char* re_vals[] = {"", "low", "medium", "high"};
                profile.reasoning_effort = (s_reasoning_effort_idx >= 0 && s_reasoning_effort_idx <= 3) ?
                    re_vals[s_reasoning_effort_idx] : "";
                profile.lmstudio_speculative_decoding = s_lmstudio_spec;
                profile.lmstudio_draft_model = s_lmstudio_draft;
                profile.mistral_codestral_url = s_mistral_codestral;
                profile.azure_deployment = s_azure_deployment;
                profile.azure_api_version = s_azure_api_ver;

                g_sa_settings.temperature  = static_cast<double>(s_temperature);
                g_sa_settings.mcp_port     = (std::min)((std::max)(s_mcp_port, 1), 65535);
                g_sa_settings.mcp_enabled  = s_mcp_enabled;
                g_sa_settings.sandbox.timeout_ms = (std::max)(s_sandbox_timeout, 1000);
                g_sa_settings.sandbox.memory_limit_mb = (std::max)(s_sandbox_memory, 64);
                g_sa_settings.sandbox.network_mode = s_sandbox_network == 1 ? "default" : "off";

                g_sa_settings.enable_reasoning = s_enable_reasoning;
                g_sa_settings.reasoning_budget = s_reasoning_budget;
                g_sa_settings.reasoning_effort = s_reasoning_effort;
                g_sa_settings.prompt_caching = s_prompt_caching;
                g_sa_settings.max_agentic_rounds = s_max_rounds;

                editor_config::tab_size = (std::max)(s_ed_tab_size, 1);
                editor_config::font_size = s_ed_font_size;
                editor_config::show_line_numbers = s_ed_line_numbers;
                editor_config::word_wrap = s_ed_word_wrap;
                editor_config::minimap = s_ed_minimap;
                editor_config::bracket_match = s_ed_bracket_match;
                editor_config::highlight_current_line = s_ed_highlight_line;
                editor_config::auto_complete = s_ed_autocomplete;
                g_sa_settings.ghost_text_enabled = s_ed_ghost_text;
                g_sa_settings.editor_tab_size = s_ed_tab_size;
                g_sa_settings.editor_font_size = s_ed_font_size;
                g_sa_settings.editor_line_numbers = s_ed_line_numbers;
                g_sa_settings.editor_word_wrap = s_ed_word_wrap;

                g_sa_settings.sync_legacy_fields_from_active_profile();

                g_sa_settings.save();

                if (g_sa_ai_client)
                    g_sa_ai_client.reset();
                g_sa_ai_client = std::make_unique<standalone_ai_client_t>(g_sa_settings);

                if (s_server_started)
                    s_mcp_server.stop();
                s_server_started = false;
                if (g_sa_settings.mcp_enabled && s_mcp_server.start(g_sa_settings.mcp_port)) {
                    s_server_started = true;
                    s_mcp_server.write_client_configs();
                }

                s_mcp_client_mgr.disconnect_all();
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
                s_mcp_client_mgr.connect_all();

                g_settings_open = false;
            }

            ImGui::SameLine(0, 6.f);

            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.15f, 0.15f, 0.20f, 0.8f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered,  ImVec4(0.22f, 0.22f, 0.28f, 0.9f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,   ImVec4(0.28f, 0.28f, 0.34f, 1.f));
            if (ImGui::Button("Cancel", ImVec2(btn_w, 28.f))) {
                s_first = true;
                g_settings_open = false;
            }
            ImGui::PopStyleColor(3);
        }
    }

    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(15);
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
    if (driver_bridge::attach(pid)) {
        output_log::push(bottom_tab_t::driver_log, "[driver] Attached to PID " + std::to_string(pid));
    } else {
        output_log::push(bottom_tab_t::driver_log, "[driver] Failed to attach to PID " + std::to_string(pid) +
                         ": " + driver_bridge::last_error());
    }
}

void do_process_detach()
{
    driver_bridge::detach();
    output_log::push(bottom_tab_t::driver_log, "[driver] Detached from process");
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
        bg = IM_COL32(38, 56, 96, 230);
        fg = IM_COL32(190, 220, 255, 245);
        return;
    }
    if (active == "build") {
        glyph = "BUILD";
        label = "BUILD";
        bg = IM_COL32(38, 80, 56, 230);
        fg = IM_COL32(190, 235, 200, 245);
        return;
    }
    glyph = active.empty() ? std::string("?") : active.substr(0, 1);
    label = active.empty() ? std::string("agent") : active;
    const aida::agent::agent_info_t* info = aida::agent::get(active);
    ImU32 col = info != nullptr
        ? hex_to_imu32_or_default(info->color, IM_COL32(96, 110, 150, 230))
        : IM_COL32(96, 110, 150, 230);
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

float chat_agent_pill_width()
{
    std::string label, glyph;
    ImU32 bg, fg;
    plan_build_pill_meta(label, glyph, bg, fg);
    ImVec2 ts = ImGui::CalcTextSize(label.c_str());
    return ts.x + 38.f;
}

void chat_render_agent_pill(float anchor_x, float anchor_y, float alpha)
{
    if (alpha <= 0.001f) return;

    std::string label, glyph;
    ImU32 bg, fg;
    plan_build_pill_meta(label, glyph, bg, fg);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 ts = ImGui::CalcTextSize(label.c_str());
    float pill_h = 22.f;
    float pad_x = 12.f;
    float gap = 6.f;
    float dot_r = 6.f;
    float pill_w = pad_x + dot_r * 2.f + gap + ts.x + pad_x;

    ImVec2 pmin(anchor_x, anchor_y);
    ImVec2 pmax(anchor_x + pill_w, anchor_y + pill_h);

    bool hov = ImGui::IsMouseHoveringRect(pmin, pmax);

    int br = (bg >> 0) & 0xFF;
    int bg_g = (bg >> 8) & 0xFF;
    int bb_v = (bg >> 16) & 0xFF;
    ImU32 fill = IM_COL32(br, bg_g, bb_v, static_cast<int>(((bg >> 24) & 0xFF) * alpha));
    ImU32 fill_hov = IM_COL32(
        std::min(255, br + 25), std::min(255, bg_g + 25), std::min(255, bb_v + 25),
        static_cast<int>(((bg >> 24) & 0xFF) * alpha));
    dl->AddRectFilled(pmin, pmax, hov ? fill_hov : fill, pill_h * 0.5f);
    dl->AddRect(pmin, pmax,
        IM_COL32(255, 255, 255, static_cast<int>((hov ? 70 : 30) * alpha)),
        pill_h * 0.5f, 0, 1.f);

    float dot_cx = pmin.x + pad_x + dot_r * 0.5f;
    float dot_cy = pmin.y + pill_h * 0.5f;
    dl->AddCircleFilled(ImVec2(dot_cx, dot_cy), dot_r,
        IM_COL32(255, 255, 255, static_cast<int>(220 * alpha)), 18);

    float text_x = dot_cx + dot_r + gap;
    int fr = (fg >> 0) & 0xFF;
    int fg_g = (fg >> 8) & 0xFF;
    int fb = (fg >> 16) & 0xFF;
    ImU32 fg_a = IM_COL32(fr, fg_g, fb, static_cast<int>(((fg >> 24) & 0xFF) * alpha));
    dl->AddText(ImVec2(text_x, pmin.y + (pill_h - ts.y) * 0.5f), fg_a, label.c_str());

    ImVec2 wp = ImGui::GetWindowPos();
    ImGui::SetCursorPos(ImVec2(pmin.x - wp.x, pmin.y - wp.y));
    ImGui::InvisibleButton("##aida_agent_pill", ImVec2(pill_w, pill_h));
    if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
        aida::agent_picker::open();
    }
    if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("Active agent: %s\nClick to switch  |  Ctrl+Shift+M to toggle plan/build  |  Ctrl+Shift+A to open picker",
            aida::agent::active_agent_name().c_str());
    }
}
