
#include <windows.h>
#include <intrin.h>

#include "mcp_standalone.hpp"
#include "mcp_client.hpp"
#include "mcp_marketplace.hpp"
#include "standalone_ai_client.hpp"
#include "standalone_license.hpp"
#include "standalone_settings.hpp"
#include "standalone_driver.hpp"
#include "zydis_disasm.hpp"

#include "../helpers/globals.h"

#include "../../../../driver/comm.h"

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

#include <nlohmann/json.hpp>

using json = nlohmann::json;

extern DisasmState g_disasm;


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


mcp_standalone::server_t s_mcp_server;
bool                     s_server_started = false;
bool                     s_initialized    = false;


mcp_client::manager_t s_mcp_client_mgr;
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


std::string build_system_prompt(bool native_tool_use = false)
{
    std::string prompt;
    prompt.reserve(8192);

    prompt +=
        "You are AiDA, a state-of-the-art reverse engineering, binary analysis, "
        "and debugging assistant. You operate through a kernel-backed live process "
        "inspection bridge (with user-mode fallback), Zydis for x64 disassembly, and Windows Sandbox for "
        "safe sample execution.\n\n"
        "## Rules\n"
        "- Be precise, technical, and concise.\n"
        "- When asked to analyze, disassemble, or inspect something, USE YOUR TOOLS.\n"
        "- Always call `driver_status` before attempting live-memory operations.\n"
        "- Call `driver_load` when the kernel backend is not active and deeper runtime access is required.\n"
        "- Call `driver_attach` with a process name or PID before reading process memory.\n"
        "- Use `disassemble_file` to load and disassemble PE files from disk.\n"
        "- Use `disassemble_address` for live memory disassembly.\n"
        "- Use `sandbox_execute` for running untrusted binaries in Windows Sandbox.\n"
        "- For number conversions, ALWAYS use `convert_number`.\n"
        "- Do NOT fabricate tool results. If you need data, call a tool.\n\n";


    if (!native_tool_use) {
        prompt += "## Available Tools\n\n";

        auto& tools = s_mcp_server.get_tools();
        for (const auto& t : tools) {
            prompt += "### " + t.name + "\n";
            prompt += t.description + "\n";
            if (!t.params.empty()) {
                prompt += "Parameters:\n";
                for (const auto& p : t.params) {
                    prompt += "- `" + p.name + "` (" + p.type;
                    if (p.required) prompt += ", required";
                    prompt += "): " + p.description + "\n";
                }
            }
            prompt += "\n";
        }
    }


    auto remote_tools = s_mcp_client_mgr.get_all_tools();
    if (!remote_tools.empty()) {
        prompt += "## External MCP Tools\n\n";
        for (const auto& rt : remote_tools) {
            prompt += "### mcp::" + rt.name + " (from " + rt.server_name + ")\n";
            prompt += rt.description + "\n";
            if (rt.input_schema.contains("properties") && rt.input_schema["properties"].is_object()) {
                prompt += "Parameters:\n";
                for (auto it = rt.input_schema["properties"].begin();
                     it != rt.input_schema["properties"].end(); ++it) {
                    prompt += "- `" + it.key() + "` (";
                    prompt += it.value().value("type", "string");
                    prompt += "): " + it.value().value("description", "") + "\n";
                }
            }
            prompt += "\n";
        }
    }

    if (!native_tool_use) {
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


std::string execute_tool(const std::string& name, const json& arguments)
{


    (void)standalone_license::verify_entitlement_state();

    output_log::push(bottom_tab_t::mcp_log, "[tool] Executing: " + name);


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

    const bool use_native = (g_sa_settings.get_active_profile_kind() == "anthropic");
    std::string system_prompt = build_system_prompt(use_native);
    const int max_turns = (std::max)(g_sa_settings.max_agentic_rounds, 1);
    int64_t budget_used = 0;


    if (use_native) {

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

            if (g_sa_settings.task_budget_tokens > 0 && budget_used >= g_sa_settings.task_budget_tokens) {
                output_log::push(bottom_tab_t::output, "[ai] Task budget exhausted (" + std::to_string(budget_used) + " tokens)");
                post_update(ai_update_t::ERR, "Task budget exhausted (" + std::to_string(budget_used) + " tokens used).");
                return;
            }

            if (turn > 0)
                post_update(ai_update_t::THINKING, "Processing tool results...");

            ai_generation_result_t gen;
            try {
                gen = g_sa_ai_client->generate_with_tools(messages, system_prompt, local_tools,
                    [](const std::string& chunk) {

                        if (!chunk.empty() && chunk[0] != '\x01')
                            post_update(ai_update_t::CHUNK, chunk);
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


            if (gen.tool_calls.empty() || gen.stop_reason != "tool_use") {

                if (gen.text.empty() && !gen.thinking.empty())
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
                    if (standalone_license::verify_gate_token(
                            standalone_license::gate_chat_tool_exec, gate) < 0.5) {
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

        output_log::push(bottom_tab_t::output, "[ai] Reached max tool rounds (" + std::to_string(max_turns) + ") [native]");
        post_update(ai_update_t::ERR, "Reached maximum tool-calling rounds (" + std::to_string(max_turns) + "). Stopping.");
        return;
    }


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

        if (g_sa_settings.task_budget_tokens > 0 && budget_used >= g_sa_settings.task_budget_tokens) {
            output_log::push(bottom_tab_t::output, "[ai] Task budget exhausted (" + std::to_string(budget_used) + " tokens)");
            post_update(ai_update_t::ERR, "Task budget exhausted (" + std::to_string(budget_used) + " tokens used).");
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
                if (standalone_license::verify_gate_token(
                        standalone_license::gate_chat_tool_exec, gate) < 0.5) {
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
    if (!device)
        return;


    if (!device->is_connected() && !device->connect())
        return;

    if (!device->refresh_heartbeat())
        return;

    const DWORD own_pid = GetCurrentProcessId();
    device->set_process_id(own_pid);
    device->solve_dtb();

    if (device->get_dtb() == 0)
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

    device->register_dll_protection(
        reinterpret_cast<std::uint64_t>(exe_module),
        text_base,
        text_size,
        text_hash,
        2000
    );
}

}


bool g_settings_open = false;


void init_standalone_chat()
{
    if (s_initialized) return;


    g_sa_settings.load();


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


    license::validated = standalone_license::initialize(g_sa_settings);
    license::saved_key = g_sa_settings.license_key;
    strncpy_s(license::key_buf, sizeof(license::key_buf),
              g_sa_settings.license_key.c_str(), _TRUNCATE);
    if (!license::validated && !standalone_license::last_error().empty())
        license::error_msg = standalone_license::last_error();
    license::check_failed = !license::validated && !license::error_msg.empty();


    g_sa_ai_client = std::make_unique<standalone_ai_client_t>(g_sa_settings);


    mcp_standalone::register_standalone_tools(s_mcp_server);
    if (g_sa_settings.mcp_enabled) {
        if (s_mcp_server.start(g_sa_settings.mcp_port)) {
            s_server_started = true;
            s_mcp_server.write_client_configs();
        }
    }


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
    s_mcp_clients_connected = true;


    mcp_marketplace::load_installed(g_sa_settings.marketplace_installed_json);
    {
        auto installed = mcp_marketplace::get_installed();
        for (auto& srv : installed) {
            if (srv.enabled && srv.auto_connect)
                mcp_marketplace::activate_server(srv);
        }
    }

    driver_bridge::initialize();
    register_standalone_protection();
    restore_workspace_state();

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
        if (s_ai_thread.joinable())
            s_ai_thread.join();
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


    if (device && device->is_connected())
        device->unregister_dll_protection();

    s_initialized = false;
}


void tick_ai_chat()
{
    if (!s_initialized) return;
    if (g_chat_messages.empty()) return;

    auto& last = g_chat_messages.back();
    if (!last.is_user || g_dummy_triggered) return;


    std::string user_text = last.text;
    g_dummy_triggered = true;


    if (!g_sa_ai_client || !g_sa_ai_client->is_available()) {
        ChatMessage ai;
        ai.is_user       = false;
        ai.has_thinking   = false;
        ai.streaming      = false;
        ai.text           = "AI not configured. Click \"Settings\" in the chat header to set your API key and model.";
        g_chat_messages.push_back(ai);
        g_chat_scroll_to_bottom = true;
        g_dummy_triggered = false;
        return;
    }


    g_think_done  = false;
    g_think_timer = 0.f;


    ChatMessage ai;
    ai.is_user       = false;
    ai.has_thinking   = true;
    ai.streaming      = true;
    ai.thinking_text  = "";
    ai.text           = "";
    g_chat_messages.push_back(ai);
    g_chat_scroll_to_bottom = true;


    std::vector<std::pair<std::string, std::string>> history;
    for (int i = 0; i < (int)g_chat_messages.size() - 2; ++i) {
        auto& m = g_chat_messages[i];
        if (!m.text.empty())
            history.emplace_back(m.is_user ? "User" : "Assistant", m.text);
    }


    {
        std::lock_guard<std::mutex> lk(s_ai_thread_mtx);
        if (s_ai_running.load()) {
            s_cancel = true;
            if (g_sa_ai_client) g_sa_ai_client->cancel();
            if (s_ai_thread.joinable())
                s_ai_thread.join();
        }
        s_cancel      = false;
        s_ai_running  = true;
        s_ai_thread   = std::thread(run_agentic,
                                    std::move(user_text),
                                    std::move(history));
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
            if (!g_think_done) g_think_done = true;
            last.text += u.text;
            g_chat_scroll_to_bottom = true;
            break;

        case ai_update_t::COMPLETE:
            last.streaming = false;
            g_think_done         = true;
            g_dummy_triggered    = false;
            s_ai_running         = false;
            g_chat_scroll_to_bottom = true;
            break;

        case ai_update_t::ERR:
            g_think_done         = true;
            if (!u.text.empty()) last.text = u.text;
            last.streaming       = false;
            g_dummy_triggered    = false;
            s_ai_running         = false;
            g_chat_scroll_to_bottom = true;
            break;
        }
    }
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


void render_settings_popup()
{
    if (!g_settings_open) return;

    ImGui::OpenPopup("##sa_settings_modal");

    float ww = globals::ui::window_w;
    float wh = globals::ui::window_h;
    float pw = 760.f, ph = 620.f;
    ImGui::SetNextWindowPos(ImVec2((ww - pw) * 0.5f, (wh - ph) * 0.5f), ImGuiCond_Appearing);
    ImGui::SetNextWindowSize(ImVec2(pw, ph), ImGuiCond_Always);

    float ax = globals::ui::accent.x, ay = globals::ui::accent.y, az = globals::ui::accent.z;

    ImGui::PushStyleColor(ImGuiCol_PopupBg,        ImVec4(0.075f, 0.075f, 0.10f, 0.97f));
    ImGui::PushStyleColor(ImGuiCol_Border,          ImVec4(1.f, 1.f, 1.f, 0.08f));
    ImGui::PushStyleColor(ImGuiCol_FrameBg,         ImVec4(0.12f, 0.12f, 0.16f, 1.f));
    ImGui::PushStyleColor(ImGuiCol_FrameBgHovered,  ImVec4(0.16f, 0.16f, 0.22f, 1.f));
    ImGui::PushStyleColor(ImGuiCol_FrameBgActive,   ImVec4(0.18f, 0.18f, 0.25f, 1.f));
    ImGui::PushStyleColor(ImGuiCol_Button,          ImVec4(ax * 0.4f, ay * 0.4f, az * 0.4f, 0.7f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered,   ImVec4(ax * 0.55f, ay * 0.55f, az * 0.55f, 0.85f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,    ImVec4(ax * 0.65f, ay * 0.65f, az * 0.65f, 1.f));
    ImGui::PushStyleColor(ImGuiCol_Header,          ImVec4(ax * 0.3f, ay * 0.3f, az * 0.3f, 0.4f));
    ImGui::PushStyleColor(ImGuiCol_HeaderHovered,   ImVec4(ax * 0.4f, ay * 0.4f, az * 0.4f, 0.6f));
    ImGui::PushStyleColor(ImGuiCol_HeaderActive,    ImVec4(ax * 0.5f, ay * 0.5f, az * 0.5f, 0.8f));
    ImGui::PushStyleColor(ImGuiCol_Text,            ImVec4(0.88f, 0.87f, 0.94f, 1.f));
    ImGui::PushStyleColor(ImGuiCol_SliderGrab,      ImVec4(ax, ay, az, 0.8f));
    ImGui::PushStyleColor(ImGuiCol_SliderGrabActive,ImVec4(ax, ay, az, 1.f));
    ImGui::PushStyleColor(ImGuiCol_CheckMark,       ImVec4(ax, ay, az, 1.f));

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,  ImVec2(18.f, 14.f));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding,  6.f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,   ImVec2(8.f, 5.f));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,    ImVec2(8.f, 8.f));

    bool still_open = true;
    static bool s_first = true;
    if (ImGui::BeginPopupModal("##sa_settings_modal", &still_open,
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove))
    {
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

        auto refresh_profile_buffers = [&]() {
            g_sa_settings.ensure_default_profiles();
            if (s_selected_profile < 0 || s_selected_profile >= (int)g_sa_settings.provider_profiles.size())
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
            for (int i = 0; i < (int)kinds.size(); ++i) {
                if (kinds[i] == sa_settings_detail::normalize_provider_kind(profile.kind)) {
                    s_kind = i;
                    break;
                }
            }
        };

        if (s_first) {
            s_first = false;
            g_sa_settings.ensure_default_profiles();
            for (int i = 0; i < (int)g_sa_settings.provider_profiles.size(); ++i) {
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
        }


        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 wp = ImGui::GetWindowPos();
        {
            const char* title = "AI Configuration";
            ImVec2 tts = ImGui::CalcTextSize(title);
            dl->AddText(ImVec2(wp.x + 18, wp.y + 14),
                IM_COL32((int)(ax*255), (int)(ay*255), (int)(az*255), 220), title);
            ImGui::Dummy(ImVec2(0, tts.y + 6));
        }

        const float list_w = 150.f;
        ImGui::BeginChild("##profiles", ImVec2(list_w, ph - 120.f), true);
        for (int i = 0; i < (int)g_sa_settings.provider_profiles.size(); ++i) {
            const bool selected = (i == s_selected_profile);
            if (ImGui::Selectable(g_sa_settings.provider_profiles[i].display_name.c_str(), selected)) {
                s_selected_profile = i;
                refresh_profile_buffers();
            }
        }
        if (ImGui::Button("+ Add", ImVec2((list_w - 10.f) * 0.48f, 24.f))) {
            provider_profile_t profile;
            profile.display_name = "New Profile";
            profile.id = sa_settings_detail::make_profile_id(profile.display_name, g_sa_settings.provider_profiles.size() + 1);
            profile.kind = "openai_compatible";
            profile.base_url = "https://api.openai.com";
            profile.model = "gpt-4.1-mini";
            profile.headers_json = "{}";
            g_sa_settings.provider_profiles.push_back(profile);
            s_selected_profile = (int)g_sa_settings.provider_profiles.size() - 1;
            refresh_profile_buffers();
        }
        ImGui::SameLine();
        if (ImGui::Button("- Remove", ImVec2((list_w - 10.f) * 0.48f, 24.f)) &&
            g_sa_settings.provider_profiles.size() > 1) {
            g_sa_settings.provider_profiles.erase(g_sa_settings.provider_profiles.begin() + s_selected_profile);
            s_selected_profile = (s_selected_profile > 0) ? (s_selected_profile - 1) : 0;
            refresh_profile_buffers();
        }
        ImGui::EndChild();

        ImGui::SameLine();
        ImGui::BeginChild("##profile_editor", ImVec2(0.f, ph - 120.f), false);

        ImGui::Text("Profile Name");
        ImGui::SetNextItemWidth(-1);
        ImGui::InputText("##profile_name", s_name, sizeof(s_name));

        ImGui::Text("Provider Kind");
        ImGui::SetNextItemWidth(-1);
        auto& kinds = settings_sa_t::provider_kinds();
        std::vector<const char*> kind_items;
        kind_items.reserve(kinds.size());
        for (auto& kind : kinds)
            kind_items.push_back(kind.c_str());
        ImGui::Combo("##provider_kind", &s_kind, kind_items.data(), (int)kind_items.size());

        ImGui::Text("Model");
        ImGui::SetNextItemWidth(-1);
        ImGui::InputText("##profile_model", s_model, sizeof(s_model));
        const auto& presets = settings_sa_t::models_for_kind(kinds[s_kind]);
        if (ImGui::BeginCombo("##model_presets", "Quick Presets")) {
            for (const auto& preset : presets) {
                if (ImGui::Selectable(preset.c_str())) {
                    snprintf(s_model, sizeof(s_model), "%s", preset.c_str());
                }
            }
            ImGui::EndCombo();
        }

        ImGui::Text("Base URL");
        ImGui::SetNextItemWidth(-1);
        ImGui::InputText("##profile_base_url", s_base_url, sizeof(s_base_url));

        ImGui::Text("API Key");
        ImGui::SetNextItemWidth(-1);
        ImGui::InputText("##profile_api_key", s_api_key, sizeof(s_api_key), ImGuiInputTextFlags_Password);

        ImGui::Text("Custom Headers (JSON)");
        ImGui::SetNextItemWidth(-1);
        ImGui::InputTextMultiline("##profile_headers", s_headers, sizeof(s_headers), ImVec2(-1.f, 90.f));

        ImGui::Checkbox("Profile Enabled", &s_enabled);
        ImGui::Checkbox("Enable MCP Server", &s_mcp_enabled);
        if (s_mcp_enabled) {
            ImGui::SameLine();
            ImGui::SetNextItemWidth(90.f);
            ImGui::InputInt("Port", &s_mcp_port, 0, 0);
        }

        ImGui::Text("Temperature");
        ImGui::SetNextItemWidth(-1);
        ImGui::SliderFloat("##temp", &s_temperature, 0.0f, 2.0f, "%.2f");

        ImGui::Separator();
        ImGui::Text("AI Features (Anthropic Claude)");

        static bool s_thinking_enabled = false;
        static int  s_thinking_budget = 10000;
        static int  s_effort_level = 2;
        static bool s_prompt_caching = true;
        static int  s_task_budget = 0;
        static bool s_web_search = false;
        static int  s_max_rounds = 15;
        static bool s_fast_mode = false;
        static bool s_redact_thinking = false;


        {
            static bool s_ai_features_init = false;
            if (!s_ai_features_init || s_first) {
                s_thinking_enabled = g_sa_settings.thinking_enabled;
                s_thinking_budget = g_sa_settings.thinking_budget;
                s_effort_level = g_sa_settings.effort_level;
                s_prompt_caching = g_sa_settings.prompt_caching;
                s_task_budget = g_sa_settings.task_budget_tokens;
                s_web_search = g_sa_settings.web_search_enabled;
                s_max_rounds = g_sa_settings.max_agentic_rounds;
                s_fast_mode = g_sa_settings.fast_mode;
                s_redact_thinking = g_sa_settings.redact_thinking;
                s_ai_features_init = true;
            }
        }

        ImGui::Checkbox("Extended Thinking", &s_thinking_enabled);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Enable interleaved thinking for deeper reasoning (Anthropic only)");
        if (s_thinking_enabled) {
            ImGui::SameLine();
            ImGui::SetNextItemWidth(120.f);
            ImGui::InputInt("Budget##think", &s_thinking_budget, 1000, 5000);
            s_thinking_budget = (std::max)(s_thinking_budget, 1024);
        }

        ImGui::Text("Effort Level");
        ImGui::SetNextItemWidth(-1);
        const char* effort_labels[] = {
            "\xc2\xa4 Low", "\xe2\x97\x90 Medium", "\xe2\x97\x91 High", "\xe2\x97\x95 Max"
        };
        ImGui::Combo("##effort", &s_effort_level, effort_labels, 4);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Controls how much effort the model puts into its response");

        ImGui::Checkbox("Prompt Caching", &s_prompt_caching);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Cache system prompts to reduce cost and latency (Anthropic only)");

        ImGui::Checkbox("Web Search", &s_web_search);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Allow the AI to search the web for information (Anthropic only)");

        ImGui::Checkbox("Fast Mode", &s_fast_mode);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Enable fast-mode for lower latency responses (Anthropic only)");

        ImGui::Checkbox("Redact Thinking", &s_redact_thinking);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Redact thinking blocks from the response for privacy (Anthropic only)");

        ImGui::Text("Max Agentic Rounds");
        ImGui::SetNextItemWidth(-1);
        ImGui::SliderInt("##max_rounds", &s_max_rounds, 1, 50);

        ImGui::Text("Task Budget (tokens, 0=unlimited)");
        ImGui::SetNextItemWidth(-1);
        ImGui::InputInt("##task_budget", &s_task_budget, 10000, 50000);
        s_task_budget = (std::max)(s_task_budget, 0);

        ImGui::Separator();
        ImGui::Text("Sandbox");

        ImGui::Text("Sandbox Timeout (ms)");
        ImGui::SetNextItemWidth(-1);
        ImGui::InputInt("##sandbox_timeout", &s_sandbox_timeout, 0, 0);
        ImGui::Text("Sandbox Memory Budget (MB)");
        ImGui::SetNextItemWidth(-1);
        ImGui::InputInt("##sandbox_memory", &s_sandbox_memory, 0, 0);
        const char* network_modes[] = {"Off", "Default"};
        ImGui::Combo("Sandbox Network", &s_sandbox_network, network_modes, IM_ARRAYSIZE(network_modes));


        ImGui::Separator();
        ImGui::Text("Editor");

        static int   s_ed_tab_size = 4;
        static float s_ed_font_size = 14.0f;
        static bool  s_ed_line_numbers = true;
        static bool  s_ed_word_wrap = false;
        static bool  s_ed_minimap = false;
        static bool  s_ed_bracket_match = true;
        static bool  s_ed_highlight_line = true;
        static bool  s_ed_autocomplete = true;
        static bool  s_ed_ghost_text = false;
        {
            static bool s_ed_init = false;
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
        }

        ImGui::Text("Tab Size");
        ImGui::SetNextItemWidth(120.f);
        ImGui::SliderInt("##ed_tab_size", &s_ed_tab_size, 1, 8);

        ImGui::Text("Font Size");
        ImGui::SetNextItemWidth(120.f);
        ImGui::SliderFloat("##ed_font_size", &s_ed_font_size, 8.0f, 32.0f, "%.0f");

        ImGui::Checkbox("Show Line Numbers", &s_ed_line_numbers);
        ImGui::Checkbox("Word Wrap", &s_ed_word_wrap);
        ImGui::Checkbox("Highlight Current Line", &s_ed_highlight_line);
        ImGui::Checkbox("Bracket Matching", &s_ed_bracket_match);
        ImGui::Checkbox("Minimap", &s_ed_minimap);
        ImGui::Checkbox("Auto-Complete", &s_ed_autocomplete);
        ImGui::Checkbox("Ghost Text (AI Suggestions)", &s_ed_ghost_text);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Show AI-generated completion suggestions as translucent text (Tab to accept)");


        ImGui::Separator();
        ImGui::Text("External MCP Servers");
        {
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
                if (s_mcp_client_sel >= 0 && s_mcp_client_sel < (int)g_sa_settings.mcp_client_servers.size()) {
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
            for (int i = 0; i < (int)g_sa_settings.mcp_client_servers.size(); ++i) {
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


            if (ImGui::SmallButton("+ Add Server")) {
                mcp_client_server_t srv;
                srv.name = "New Server";
                srv.url = "http://localhost:3001";
                g_sa_settings.mcp_client_servers.push_back(srv);
                s_mcp_client_sel = (int)g_sa_settings.mcp_client_servers.size() - 1;
                refresh_mcp_cl();
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("- Remove") &&
                s_mcp_client_sel >= 0 && s_mcp_client_sel < (int)g_sa_settings.mcp_client_servers.size())
            {
                g_sa_settings.mcp_client_servers.erase(
                    g_sa_settings.mcp_client_servers.begin() + s_mcp_client_sel);
                if (s_mcp_client_sel > 0) --s_mcp_client_sel;
                refresh_mcp_cl();
            }


            if (s_mcp_client_sel >= 0 && s_mcp_client_sel < (int)g_sa_settings.mcp_client_servers.size()) {
                ImGui::Text("Server Name"); ImGui::SetNextItemWidth(-1);
                ImGui::InputText("##mcp_cl_name", s_mcp_cl_name, sizeof(s_mcp_cl_name));

                const char* transports[] = {"HTTP/SSE", "Stdio"};
                ImGui::Text("Transport"); ImGui::SetNextItemWidth(-1);
                ImGui::Combo("##mcp_cl_transport", &s_mcp_cl_transport, transports, 2);

                if (s_mcp_cl_transport == 0) {
                    ImGui::Text("URL"); ImGui::SetNextItemWidth(-1);
                    ImGui::InputText("##mcp_cl_url", s_mcp_cl_url, sizeof(s_mcp_cl_url));
                    ImGui::Text("API Key"); ImGui::SetNextItemWidth(-1);
                    ImGui::InputText("##mcp_cl_key", s_mcp_cl_key, sizeof(s_mcp_cl_key), ImGuiInputTextFlags_Password);
                } else {
                    ImGui::Text("Command"); ImGui::SetNextItemWidth(-1);
                    ImGui::InputText("##mcp_cl_cmd", s_mcp_cl_cmd, sizeof(s_mcp_cl_cmd));
                    ImGui::Text("Arguments"); ImGui::SetNextItemWidth(-1);
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

        ImGui::EndChild();

        ImGui::Dummy(ImVec2(0, 6));


        float btn_w = 100.f;
        float btn_spacing = 12.f;
        float total_btn_w = btn_w * 2 + btn_spacing;
        ImGui::SetCursorPosX((pw - total_btn_w) * 0.5f - 9.f);

        if (ImGui::Button("Save", ImVec2(btn_w, 30))) {
            if (s_selected_profile < 0 || s_selected_profile >= (int)g_sa_settings.provider_profiles.size())
                s_selected_profile = 0;
            auto& profile = g_sa_settings.provider_profiles[s_selected_profile];
            profile.display_name = s_name[0] ? s_name : "Profile";
            profile.kind = kinds[s_kind];
            profile.base_url = s_base_url;
            profile.api_key = s_api_key;
            profile.model = s_model;
            profile.headers_json = s_headers;
            profile.enabled = s_enabled;
            g_sa_settings.active_provider_profile_id = profile.id;

            g_sa_settings.temperature  = static_cast<double>(s_temperature);
            g_sa_settings.mcp_port     = (std::min)((std::max)(s_mcp_port, 1), 65535);
            g_sa_settings.mcp_enabled  = s_mcp_enabled;
            g_sa_settings.sandbox.timeout_ms = (std::max)(s_sandbox_timeout, 1000);
            g_sa_settings.sandbox.memory_limit_mb = (std::max)(s_sandbox_memory, 64);
            g_sa_settings.sandbox.network_mode = s_sandbox_network == 1 ? "default" : "off";


            g_sa_settings.thinking_enabled = s_thinking_enabled;
            g_sa_settings.thinking_budget = s_thinking_budget;
            g_sa_settings.effort_level = s_effort_level;
            g_sa_settings.prompt_caching = s_prompt_caching;
            g_sa_settings.task_budget_tokens = s_task_budget;
            g_sa_settings.web_search_enabled = s_web_search;
            g_sa_settings.max_agentic_rounds = s_max_rounds;
            g_sa_settings.fast_mode = s_fast_mode;
            g_sa_settings.redact_thinking = s_redact_thinking;


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

            g_sa_settings.apply_legacy_fields_to_active_profile();
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
            ImGui::CloseCurrentPopup();
        }

        ImGui::SameLine(0, btn_spacing);

        ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.22f, 0.22f, 0.28f, 0.8f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered,  ImVec4(0.30f, 0.30f, 0.38f, 0.9f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,   ImVec4(0.36f, 0.36f, 0.44f, 1.f));
        if (ImGui::Button("Cancel", ImVec2(btn_w, 30))) {
            s_first = true;
            g_settings_open = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::PopStyleColor(3);

        ImGui::EndPopup();
    }

    if (!still_open) {
        s_first = true;
        g_settings_open = false;
    }

    ImGui::PopStyleVar(5);
    ImGui::PopStyleColor(15);
}


mcp_client::manager_t& get_mcp_client_manager()
{
    return s_mcp_client_mgr;
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
    return driver_bridge::is_loaded();
}

std::string get_attached_process_name()
{
    return driver_bridge::status();
}

unsigned long get_attached_pid()
{
    return 0;
}
