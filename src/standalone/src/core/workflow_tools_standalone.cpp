#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "mcp_standalone.hpp"
#include "agent_registry.hpp"
#include "standalone_settings.hpp"
#include "apply_diff.hpp"
#include "apply_patch.hpp"
#include "code_index.hpp"
#include "checkpoints.hpp"
#define AIDA_SKILLS_IMPLEMENTATION
#include "skills.hpp"
#include "tool_repetition.hpp"
#include "event_bus.hpp"
#include "session_store.hpp"

#include "../helpers/globals.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <mutex>
#include <algorithm>
#include <chrono>

#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;


namespace
{

std::string              g_task_todo;
std::mutex               g_todo_mtx;

std::string              g_completion_result;
std::string              g_completion_command;
std::mutex               g_completion_mtx;
bool                     g_completion_pending = false;

std::string              g_followup_question;
std::vector<std::string> g_followup_options;
std::mutex               g_followup_mtx;
bool                     g_followup_pending = false;

tool_repetition::detector_t g_repetition_detector;


std::unique_ptr<code_index::manager_t> g_code_index;
std::mutex                              g_code_index_mtx;


std::unique_ptr<checkpoints::service_t> g_checkpoint_svc;
std::mutex                               g_checkpoint_mtx;
std::string                              g_task_id = "default";


std::unique_ptr<skills::manager_t> g_skills_mgr;
std::mutex                          g_skills_mtx;
std::string                         g_workspace_root;


tool_result_t handle_switch_agent(const json& params)
{
    std::string name;
    if (params.contains("agent") && params["agent"].is_string())
        name = params["agent"].get<std::string>();
    else if (params.contains("name") && params["name"].is_string())
        name = params["name"].get<std::string>();
    else if (params.contains("agent_name") && params["agent_name"].is_string())
        name = params["agent_name"].get<std::string>();
    if (name.empty())
        return tool_result_t::error("Missing required parameter: agent");

    std::string reason;
    if (params.contains("reason") && params["reason"].is_string())
        reason = params["reason"].get<std::string>();

    const auto* info = aida::agent::get(name);
    if (info == nullptr)
        return tool_result_t::error("Unknown agent: " + name + ". Use list_agents to see available agents.");

    std::string previous = aida::agent::active_agent_name();
    if (!aida::agent::set_active_agent(name))
        return tool_result_t::error("Failed to switch agent: " + aida::agent::last_error());

    if (previous != name) {
        aida::events::agent_changed_t evt;
        evt.session_id = conversations::current_id;
        evt.previous_agent = previous;
        evt.new_agent = name;
        aida::events::publish(aida::events::event_agent_changed, evt);
    }

    std::string msg = std::string("Switched to '") + name + "' agent.";
    if (!reason.empty())
        msg += " Reason: " + reason;

    output_log::push(bottom_tab_t::output, "[agent] " + msg);
    return tool_result_t::ok(msg);
}


tool_result_t handle_plan_enter(const json& )
{
    if (aida::agent::active_agent_name() == "plan")
        return tool_result_t::ok("Already in plan mode.");

    std::string previous = aida::agent::active_agent_name();
    if (!aida::agent::set_active_agent("plan"))
        return tool_result_t::error("Failed to enter plan mode: " + aida::agent::last_error());

    aida::events::agent_changed_t evt;
    evt.session_id = conversations::current_id;
    evt.previous_agent = previous;
    evt.new_agent = "plan";
    aida::events::publish(aida::events::event_agent_changed, evt);

    output_log::push(bottom_tab_t::output, "[agent] Entered plan mode (previous: " + previous + ")");

    return tool_result_t::ok(
        "Entered plan mode. Edit/write/bash tools are now blocked. "
        "Use plan_exit when ready to execute.");
}


tool_result_t handle_plan_exit(const json& params)
{
    if (aida::agent::active_agent_name() != "plan")
        return tool_result_t::error("Not in plan mode.");

    std::string summary;
    if (params.contains("summary") && params["summary"].is_string())
        summary = params["summary"].get<std::string>();

    std::string handoff_text = summary;
    if (!handoff_text.empty()) handoff_text += "\n\n";
    handoff_text += "<plan_exit_handoff>";

    int64_t now_ms = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());

    std::string session_id = conversations::current_id;
    if (!session_id.empty())
    {
        aida::session::message_t um;
        um.id = session_id + "-plan-exit-" + std::to_string(now_ms);
        um.session_id = session_id;
        um.role = aida::session::message_t::role_t::user;
        um.agent = "build";
        aida::session::part_t pt;
        pt.kind = aida::session::part_t::kind_t::text;
        pt.text.text = handoff_text;
        pt.text.synthetic = true;
        um.parts.push_back(pt);
        um.created_unix = now_ms / 1000;
        (void)aida::session::append_message(um);
    }

    {
        ChatMessage cm;
        cm.text = handoff_text;
        cm.is_user = true;
        cm.timestamp = now_ms;
        g_chat_messages.push_back(cm);
        g_chat_scroll_to_bottom = true;
    }

    if (!aida::agent::set_active_agent("build"))
        return tool_result_t::error("Failed to switch to build agent: " + aida::agent::last_error());

    aida::events::agent_changed_t evt;
    evt.session_id = session_id;
    evt.previous_agent = "plan";
    evt.new_agent = "build";
    aida::events::publish(aida::events::event_agent_changed, evt);

    output_log::push(bottom_tab_t::output,
        std::string("[agent] plan_exit: switching to build agent") +
        (summary.empty() ? std::string{} : std::string(" (summary: ") + summary.substr(0, 80) + ")"));

    return tool_result_t::ok("Plan complete. Switching to build agent to execute.");
}


tool_result_t handle_task(const json& params)
{
    std::string agent_name;
    if (params.contains("agent") && params["agent"].is_string())
        agent_name = params["agent"].get<std::string>();
    else if (params.contains("name") && params["name"].is_string())
        agent_name = params["name"].get<std::string>();
    if (agent_name.empty())
        return tool_result_t::error("Missing required parameter: agent");

    std::string prompt;
    if (params.contains("prompt") && params["prompt"].is_string())
        prompt = params["prompt"].get<std::string>();
    else if (params.contains("description") && params["description"].is_string())
        prompt = params["description"].get<std::string>();
    if (prompt.empty())
        return tool_result_t::error("Missing required parameter: prompt");

    int max_steps = 0;
    if (params.contains("max_steps") && params["max_steps"].is_number_integer())
        max_steps = params["max_steps"].get<int>();

    const aida::agent::agent_info_t* info = aida::agent::get(agent_name);
    if (info == nullptr)
        return tool_result_t::error("Unknown agent: " + agent_name);
    if (info->mode == aida::agent::agent_info_t::mode_t::primary)
        return tool_result_t::error(
            "Agent '" + agent_name + "' is a primary agent and cannot be invoked as a subagent. "
            "Use the 'switch_agent' tool to switch the conversation to it instead.");

    std::string parent_session_id;

    output_log::push(bottom_tab_t::output, "[task] Spawning subagent: " + agent_name);

    std::string result;
    bool ok = aida::agent::task::execute(agent_name, prompt, max_steps, parent_session_id, result);
    if (!ok && result.empty())
        return tool_result_t::error("Subagent failed: " + aida::agent::task::last_error());
    return tool_result_t::ok(result);
}


tool_result_t handle_list_agents(const json&)
{
    std::string out = "Available agents:\n";
    json arr = json::array();
    auto primaries = aida::agent::primary_agents();
    auto subs = aida::agent::subagents();
    for (const auto* a : primaries) {
        out += "- " + a->name + " (primary): " + a->description + "\n";
        arr.push_back({{"name", a->name}, {"mode", "primary"}, {"description", a->description}, {"hidden", a->hidden}});
    }
    for (const auto* a : subs) {
        out += "- " + a->name + " (subagent): " + a->description + "\n";
        arr.push_back({{"name", a->name}, {"mode", "subagent"}, {"description", a->description}, {"hidden", a->hidden}});
    }
    return tool_result_t::ok(out, json{{"agents", arr}});
}


tool_result_t handle_ask_followup_question(const json& params)
{
    if (!params.contains("question") || !params["question"].is_string())
        return tool_result_t::error("Missing required parameter: question");

    std::string question = params["question"].get<std::string>();
    std::vector<std::string> options;

    if (params.contains("options") && params["options"].is_array()) {
        for (const auto& opt : params["options"]) {
            if (opt.is_string())
                options.push_back(opt.get<std::string>());
        }
    }

    {
        std::lock_guard<std::mutex> lk(g_followup_mtx);
        g_followup_question = question;
        g_followup_options = options;
        g_followup_pending = true;
    }

    std::string msg = "Follow-up question presented to user: " + question;
    if (!options.empty()) {
        msg += "\nOptions: ";
        for (size_t i = 0; i < options.size(); ++i) {
            if (i > 0) msg += ", ";
            msg += options[i];
        }
    }

    return tool_result_t::ok(msg);
}


tool_result_t handle_attempt_completion(const json& params)
{
    if (!params.contains("result") || !params["result"].is_string())
        return tool_result_t::error("Missing required parameter: result");

    std::string result = params["result"].get<std::string>();
    std::string command;

    if (params.contains("command") && params["command"].is_string())
        command = params["command"].get<std::string>();

    {
        std::lock_guard<std::mutex> lk(g_completion_mtx);
        g_completion_result = result;
        g_completion_command = command;
        g_completion_pending = true;
    }

    std::string msg = "Task completion attempted.\nResult: " + result;
    if (!command.empty())
        msg += "\nVerification command: " + command;

    return tool_result_t::ok(msg);
}


tool_result_t handle_update_todo_list(const json& params)
{
    if (!params.contains("content") || !params["content"].is_string())
        return tool_result_t::error("Missing required parameter: content");

    std::string content = params["content"].get<std::string>();

    {
        std::lock_guard<std::mutex> lk(g_todo_mtx);
        g_task_todo = content;
    }

    int total = 0, done = 0;
    std::istringstream ss(content);
    std::string line;
    while (std::getline(ss, line)) {
        if (line.find("- [") != std::string::npos) {
            ++total;
            if (line.find("- [x]") != std::string::npos || line.find("- [X]") != std::string::npos)
                ++done;
        }
    }

    std::string msg = "Todo list updated. " + std::to_string(done) + "/" + std::to_string(total) + " items completed.";
    return tool_result_t::ok(msg);
}


tool_result_t handle_apply_diff(const json& params)
{
    if (!params.contains("path") || !params["path"].is_string())
        return tool_result_t::error("Missing required parameter: path");
    if (!params.contains("diff") || !params["diff"].is_string())
        return tool_result_t::error("Missing required parameter: diff");

    std::string path = params["path"].get<std::string>();
    std::string diff_text = params["diff"].get<std::string>();

    if (!fs::exists(path))
        return tool_result_t::error("File not found: " + path);

    std::ifstream ifs(path);
    if (!ifs)
        return tool_result_t::error("Cannot read file: " + path);

    std::string original((std::istreambuf_iterator<char>(ifs)),
                          std::istreambuf_iterator<char>());
    ifs.close();

    auto result = apply_diff::apply(original, diff_text);
    if (!result.success)
        return tool_result_t::error("Failed to apply diff: " + result.error);

    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs)
        return tool_result_t::error("Cannot write file: " + path);

    ofs << result.content;
    ofs.close();

    std::string msg = "Applied diff to " + path + " successfully.";
    output_log::push(bottom_tab_t::output, "[diff] " + msg);
    return tool_result_t::ok(msg);
}


tool_result_t handle_apply_patch(const json& params)
{
    if (!params.contains("patch") || !params["patch"].is_string())
        return tool_result_t::error("Missing required parameter: patch");

    std::string patch_text = params["patch"].get<std::string>();

    auto read_fn = [](const std::string& path) -> std::string {
        std::ifstream ifs(path);
        if (!ifs) return "";
        return std::string((std::istreambuf_iterator<char>(ifs)),
                            std::istreambuf_iterator<char>());
    };

    auto write_fn = [](const std::string& path, const std::string& content) -> bool {
        fs::create_directories(fs::path(path).parent_path());
        std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
        if (!ofs) return false;
        ofs << content;
        return true;
    };

    auto delete_fn = [](const std::string& path) -> bool {
        std::error_code ec;
        return fs::remove(path, ec);
    };

    auto move_fn = [](const std::string& from, const std::string& to) -> bool {
        fs::create_directories(fs::path(to).parent_path());
        std::error_code ec;
        fs::rename(from, to, ec);
        return !ec;
    };

    auto result = apply_patch::apply(patch_text, read_fn, write_fn, delete_fn, move_fn);

    if (!result.success) {
        return tool_result_t::error("Patch application failed: " + result.error);
    }

    int files_modified = static_cast<int>(result.modified_files.size());
    int files_deleted = static_cast<int>(result.deleted_files.size());
    int files_moved = static_cast<int>(result.moved_files.size());

    std::string msg = "Patch applied: " +
                     std::to_string(files_modified) + " modified, " +
                     std::to_string(files_deleted) + " deleted, " +
                     std::to_string(files_moved) + " moved.";
    output_log::push(bottom_tab_t::output, "[patch] " + msg);
    return tool_result_t::ok(msg);
}


tool_result_t handle_codebase_search(const json& params)
{
    if (!params.contains("query") || !params["query"].is_string())
        return tool_result_t::error("Missing required parameter: query");

    std::string query = params["query"].get<std::string>();
    std::string directory;
    if (params.contains("directory") && params["directory"].is_string())
        directory = params["directory"].get<std::string>();

    std::lock_guard<std::mutex> lk(g_code_index_mtx);
    if (!g_code_index) {
        if (g_sa_settings.workspace.root_path.empty())
            return tool_result_t::error("No workspace is open. Open a workspace first.");

        g_code_index = std::make_unique<code_index::manager_t>(g_sa_settings.workspace.root_path);
        g_code_index->start_indexing();
        return tool_result_t::ok("Code index is being built. Please retry in a moment.");
    }

    if (g_code_index->state() == code_index::index_state_t::indexing)
        return tool_result_t::ok("Code index is still building. Please retry in a moment. " +
                                std::to_string(g_code_index->indexed_count()) + " documents indexed so far.");

    auto results = g_code_index->search(query, directory, 10);

    if (results.empty())
        return tool_result_t::ok("No results found for query: " + query);

    json results_json = json::array();
    for (const auto& r : results) {
        results_json.push_back({
            {"file", r.file_path},
            {"line", r.line_number},
            {"score", r.score},
            {"content", r.content}
        });
    }

    return tool_result_t::ok(
        "Found " + std::to_string(results.size()) + " results for: " + query,
        json{{"results", results_json}});
}


tool_result_t handle_read_command_output(const json& params)
{
    if (!params.contains("id") || !params["id"].is_string())
        return tool_result_t::error("Missing required parameter: id");

    std::string id = params["id"].get<std::string>();

    return tool_result_t::ok("Terminal output for session " + id + " is not yet available. "
                            "The terminal integration requires ConPTY session tracking.");
}


tool_result_t handle_save_checkpoint(const json& params)
{
    std::string message;
    if (params.contains("message") && params["message"].is_string())
        message = params["message"].get<std::string>();

    std::lock_guard<std::mutex> lk(g_checkpoint_mtx);
    if (!g_checkpoint_svc) {
        if (g_sa_settings.workspace.root_path.empty())
            return tool_result_t::error("No workspace is open.");

        g_checkpoint_svc = std::make_unique<checkpoints::service_t>(
            g_sa_settings.workspace.root_path);

        char appdata[MAX_PATH];
        GetEnvironmentVariableA("APPDATA", appdata, MAX_PATH);
        std::string checkpoint_dir = std::string(appdata) + "\\AiDA\\Standalone\\checkpoints";
        g_checkpoint_svc->set_storage_dir(checkpoint_dir);
    }

    std::vector<std::string> tracked;
    bool ok = g_checkpoint_svc->save_checkpoint(g_task_id, message, 0, tracked);
    if (!ok)
        return tool_result_t::error("Failed to save checkpoint.");

    return tool_result_t::ok("Checkpoint saved." +
                            (message.empty() ? std::string{} : " (" + message + ")"));
}


tool_result_t handle_restore_checkpoint(const json& params)
{
    if (!params.contains("checkpoint_id") || !params["checkpoint_id"].is_string())
        return tool_result_t::error("Missing required parameter: checkpoint_id");

    std::string id = params["checkpoint_id"].get<std::string>();

    std::lock_guard<std::mutex> lk(g_checkpoint_mtx);
    if (!g_checkpoint_svc)
        return tool_result_t::error("No checkpoints available. Save a checkpoint first.");

    bool ok = g_checkpoint_svc->restore_checkpoint(g_task_id, id);
    if (!ok)
        return tool_result_t::error("Failed to restore checkpoint: " + id);

    return tool_result_t::ok("Checkpoint " + id + " restored successfully.");
}


tool_result_t handle_list_checkpoints(const json& )
{
    std::lock_guard<std::mutex> lk(g_checkpoint_mtx);
    if (!g_checkpoint_svc)
        return tool_result_t::ok("No checkpoints available.");

    auto cps = g_checkpoint_svc->list_checkpoints(g_task_id);
    if (cps.empty())
        return tool_result_t::ok("No checkpoints saved yet.");

    json arr = json::array();
    for (const auto& cp : cps) {
        arr.push_back({
            {"id", cp.id},
            {"message", cp.message},
            {"timestamp", cp.timestamp},
            {"files", static_cast<int>(cp.files.size())}
        });
    }

    return tool_result_t::ok(
        std::to_string(cps.size()) + " checkpoint(s) available.",
        json{{"checkpoints", arr}});
}


tool_result_t handle_skill(const json& params)
{
    if (!params.contains("name") || !params["name"].is_string())
        return tool_result_t::error("Missing required parameter: name");

    std::string name = params["name"].get<std::string>();
    std::string arguments;
    if (params.contains("arguments") && params["arguments"].is_string())
        arguments = params["arguments"].get<std::string>();

    std::lock_guard<std::mutex> lk(g_skills_mtx);
    if (!g_skills_mgr) {
        std::string workspace = g_sa_settings.workspace.root_path;
        if (workspace.empty())
            return tool_result_t::error("No workspace is open.");

        char appdata[MAX_PATH];
        GetEnvironmentVariableA("APPDATA", appdata, MAX_PATH);
        std::string global_dir = std::string(appdata) + "\\AiDA\\Standalone\\skills";

        g_skills_mgr = std::make_unique<skills::manager_t>();
        g_skills_mgr->add_search_path(workspace + "/.aida/skills");
        g_skills_mgr->add_search_path(global_dir);
        g_skills_mgr->discover();
    }

    if (!g_skills_mgr->has_skill(name))
        return tool_result_t::error("Skill not found: " + name);

    auto result = g_skills_mgr->resolve(name);

    std::string response = "## Skill: " + result.name + "\n\n";
    if (!result.description.empty())
        response += result.description + "\n\n";
    if (!arguments.empty())
        response += "**Arguments:** " + arguments + "\n\n";
    response += "---\n\n" + result.instructions;

    return tool_result_t::ok(response);
}


tool_result_t handle_run_slash_command(const json& params)
{
    if (!params.contains("command") || !params["command"].is_string())
        return tool_result_t::error("Missing required parameter: command");

    std::string command = params["command"].get<std::string>();
    std::string arguments;
    if (params.contains("arguments") && params["arguments"].is_string())
        arguments = params["arguments"].get<std::string>();

    if (command == "help") {
        return tool_result_t::ok(
            "Available slash commands:\n"
            "- /help - Show available commands\n"
            "- /clear - Clear the chat history\n"
            "- /agent <name> - Switch to an agent (build, plan, general, explore)\n"
            "- /agents - List available agents\n"
            "- /checkpoint [message] - Save a checkpoint\n"
            "- /restore <id> - Restore a checkpoint\n"
            "- /skills - List available skills\n"
            "- /index - Rebuild the code index\n");
    }

    if (command == "clear") {
        g_chat_messages.clear();
        return tool_result_t::ok("Chat history cleared.");
    }

    if (command == "agent") {
        if (arguments.empty())
            return tool_result_t::error("Usage: /agent <name>");
        json p;
        p["agent"] = arguments;
        return handle_switch_agent(p);
    }

    if (command == "agents") {
        return handle_list_agents(json::object());
    }

    if (command == "checkpoint") {
        json p;
        if (!arguments.empty()) p["message"] = arguments;
        return handle_save_checkpoint(p);
    }

    if (command == "restore") {
        if (arguments.empty())
            return tool_result_t::error("Usage: /restore <checkpoint_id>");
        json p;
        p["checkpoint_id"] = arguments;
        return handle_restore_checkpoint(p);
    }

    if (command == "skills") {
        std::lock_guard<std::mutex> lk(g_skills_mtx);
        if (!g_skills_mgr)
            return tool_result_t::ok("No skills discovered yet. Open a workspace first.");

        auto all = g_skills_mgr->get_all();
        if (all.empty())
            return tool_result_t::ok("No skills available.");

        std::string msg = "Available skills:\n";
        for (const auto& s : all) {
            msg += "- **" + s.name + "**: " + s.description + "\n";
        }
        return tool_result_t::ok(msg);
    }

    if (command == "index") {
        std::lock_guard<std::mutex> lk(g_code_index_mtx);
        if (!g_code_index) {
            if (g_sa_settings.workspace.root_path.empty())
                return tool_result_t::error("No workspace is open.");
            g_code_index = std::make_unique<code_index::manager_t>(g_sa_settings.workspace.root_path);
        }
        g_code_index->start_indexing();
        return tool_result_t::ok("Code index rebuild started.");
    }

    return tool_result_t::error("Unknown slash command: /" + command);
}

}


namespace workflow_tools
{

std::string get_todo_list()
{
    std::lock_guard<std::mutex> lk(g_todo_mtx);
    return g_task_todo;
}

bool is_completion_pending()
{
    std::lock_guard<std::mutex> lk(g_completion_mtx);
    return g_completion_pending;
}

std::string get_completion_result()
{
    std::lock_guard<std::mutex> lk(g_completion_mtx);
    return g_completion_result;
}

std::string get_completion_command()
{
    std::lock_guard<std::mutex> lk(g_completion_mtx);
    return g_completion_command;
}

void clear_completion()
{
    std::lock_guard<std::mutex> lk(g_completion_mtx);
    g_completion_pending = false;
    g_completion_result.clear();
    g_completion_command.clear();
}

bool is_followup_pending()
{
    std::lock_guard<std::mutex> lk(g_followup_mtx);
    return g_followup_pending;
}

std::string get_followup_question()
{
    std::lock_guard<std::mutex> lk(g_followup_mtx);
    return g_followup_question;
}

std::vector<std::string> get_followup_options()
{
    std::lock_guard<std::mutex> lk(g_followup_mtx);
    return g_followup_options;
}

void clear_followup()
{
    std::lock_guard<std::mutex> lk(g_followup_mtx);
    g_followup_pending = false;
    g_followup_question.clear();
    g_followup_options.clear();
}

tool_repetition::detector_t& get_repetition_detector()
{
    return g_repetition_detector;
}


void initialize_code_index(const std::string& workspace_root)
{
    std::lock_guard<std::mutex> lk(g_code_index_mtx);
    if (!g_code_index) {
        g_code_index = std::make_unique<code_index::manager_t>(workspace_root);
        g_code_index->start_indexing();
    }
}

void shutdown_services()
{
    {
        std::lock_guard<std::mutex> lk(g_code_index_mtx);
        if (g_code_index) {
            g_code_index->stop_indexing();
            g_code_index.reset();
        }
    }
    {
        std::lock_guard<std::mutex> lk(g_checkpoint_mtx);
        g_checkpoint_svc.reset();
    }
    {
        std::lock_guard<std::mutex> lk(g_skills_mtx);
        g_skills_mgr.reset();
    }
}


void register_workflow_tools(mcp_standalone::server_t& srv)
{
    srv.register_tool({"switch_agent",
        "Switch the current operating agent. Built-in primary agents: build (default), plan. "
        "Subagents (build/plan only) cannot be activated as primary.",
        {{"agent", "string", "Agent name (e.g. 'build', 'plan')", true},
         {"reason", "string", "Why you are switching agents", false}},
        false, handle_switch_agent});

    srv.register_tool({"plan_enter",
        "Enter PLAN mode. Use this when the user's request would benefit from planning before "
        "implementation. Plan mode is read-only: edit/write/bash and other mutation tools become "
        "hard-denied. Once a plan is ready, call plan_exit to switch to the build agent. Call this "
        "tool when: the user explicitly asks for a plan; the request is complex enough to benefit "
        "from research and design first; the task involves multiple files or architectural decisions. "
        "Do NOT call for trivial single-step tasks or when the user has asked for immediate execution.",
        {},
        true, handle_plan_enter});

    srv.register_tool({"plan_exit",
        "Exit PLAN mode and switch to the build agent so the plan can be executed. Inserts a "
        "synthetic user handoff message into the session, then switches to the build agent. "
        "Call this only after the plan is fully written, all clarifying questions are answered, "
        "and the user has confirmed (explicitly or implicitly) they are ready to execute.",
        {{"summary", "string", "Optional one-paragraph plan summary that will be attached to the handoff message.", false}},
        false, handle_plan_exit});

    srv.register_tool({"task",
        "Spawn a subagent in an isolated context to perform a focused task and return its final result. "
        "Available subagents: 'general' (multi-step research), 'explore' (read-only file/binary search). "
        "The subagent runs concurrently with its own LLM client and tool stack.",
        {{"agent", "string", "Subagent name ('general' or 'explore')", true},
         {"prompt", "string", "The task description / instructions for the subagent", true},
         {"max_steps", "number", "Maximum tool-use turns the subagent may take (default 16, max 64)", false}},
        false, handle_task});

    srv.register_tool({"list_agents",
        "List all registered agents (primary and subagent), including custom user-defined ones.",
        {}, true, handle_list_agents});

    srv.register_tool({"ask_followup_question",
        "Ask the user a clarifying question. Use this when you need more information before proceeding.",
        {{"question", "string", "The question to ask the user", true},
         {"options", "array", "Optional list of suggested answers", false}},
        true, handle_ask_followup_question});

    srv.register_tool({"attempt_completion",
        "Signal that you believe the task is complete. Present your result to the user for approval.",
        {{"result", "string", "A summary of what was accomplished", true},
         {"command", "string", "An optional command the user can run to verify", false}},
        true, handle_attempt_completion});

    srv.register_tool({"update_todo_list",
        "Update the task's todo list. Use markdown checkbox format: - [ ] item or - [x] done item.",
        {{"content", "string", "The full todo list in markdown format", true}},
        true, handle_update_todo_list});

    srv.register_tool({"apply_diff",
        "Apply a unified diff to a file. Use standard unified diff format with @@ hunks.",
        {{"path", "string", "Path to the file to modify", true},
         {"diff", "string", "The unified diff content to apply", true}},
        false, handle_apply_diff});

    srv.register_tool({"apply_patch",
        "Apply a multi-file patch in Codex format. Supports adding, deleting, updating, and moving files.",
        {{"patch", "string", "The patch content in *** Begin Patch / *** End Patch format", true}},
        false, handle_apply_patch});

    srv.register_tool({"codebase_search",
        "Search the codebase for semantically relevant code. Returns matching code with file paths and line numbers.",
        {{"query", "string", "The search query describing what you're looking for", true},
         {"directory", "string", "Optional directory prefix to scope the search", false}},
        true, handle_codebase_search});

    srv.register_tool({"read_command_output",
        "Read output from a previously started background command by its terminal session ID.",
        {{"id", "string", "The terminal session ID to read output from", true}},
        true, handle_read_command_output});

    srv.register_tool({"save_checkpoint",
        "Save a checkpoint of the current workspace state. Use before making significant changes.",
        {{"message", "string", "Optional description for this checkpoint", false}},
        false, handle_save_checkpoint});

    srv.register_tool({"restore_checkpoint",
        "Restore the workspace to a previously saved checkpoint.",
        {{"checkpoint_id", "string", "The ID of the checkpoint to restore", true}},
        false, handle_restore_checkpoint});

    srv.register_tool({"list_checkpoints",
        "List all saved checkpoints for the current workspace.",
        {}, true, handle_list_checkpoints});

    srv.register_tool({"skill",
        "Invoke a registered skill by name. Skills provide specialized instructions for specific tasks.",
        {{"name", "string", "The name of the skill to invoke", true},
         {"arguments", "string", "Optional arguments to pass to the skill", false}},
        true, handle_skill});

    srv.register_tool({"run_slash_command",
        "Execute a slash command. Available: /help, /clear, /mode, /checkpoint, /restore, /skills, /index.",
        {{"command", "string", "The command name (without the leading /)", true},
         {"arguments", "string", "Optional arguments for the command", false}},
        false, handle_run_slash_command});
}

}
