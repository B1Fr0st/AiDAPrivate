#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "mcp_standalone.hpp"
#include "standalone_modes.hpp"
#include "standalone_settings.hpp"
#include "apply_diff.hpp"
#include "apply_patch.hpp"
#include "code_index.hpp"
#include "checkpoints.hpp"
#include "skills.hpp"
#include "tool_repetition.hpp"

#include "../helpers/globals.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <mutex>
#include <algorithm>

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


tool_result_t handle_switch_mode(const json& params)
{
    if (!params.contains("mode_slug") || !params["mode_slug"].is_string())
        return tool_result_t::error("Missing required parameter: mode_slug");

    std::string slug = params["mode_slug"].get<std::string>();
    std::string reason;
    if (params.contains("reason") && params["reason"].is_string())
        reason = params["reason"].get<std::string>();

    const auto* mode = aida_modes::find_mode(slug);
    if (!mode)
        return tool_result_t::error("Unknown mode: " + slug + ". Available: agent, code, architect, ask, debug");

    aida_modes::set_active_mode(slug);

    std::string msg = "Switched to " + mode->display_name + " mode.";
    if (!reason.empty())
        msg += " Reason: " + reason;

    output_log::push(bottom_tab_t::output, "[mode] " + msg);
    return tool_result_t::ok(msg);
}


tool_result_t handle_new_task(const json& params)
{
    if (!params.contains("mode") || !params["mode"].is_string())
        return tool_result_t::error("Missing required parameter: mode");
    if (!params.contains("message") || !params["message"].is_string())
        return tool_result_t::error("Missing required parameter: message");

    std::string mode = params["mode"].get<std::string>();
    std::string message = params["message"].get<std::string>();

    const auto* mode_cfg = aida_modes::find_mode(mode);
    if (!mode_cfg)
        return tool_result_t::error("Unknown mode: " + mode);

    std::string result = "New task created in " + mode_cfg->display_name + " mode.\n"
                        "Task message: " + message + "\n"
                        "Note: Sub-task execution will be handled by the orchestrator. "
                        "The task has been queued for processing.";

    output_log::push(bottom_tab_t::output, "[task] New sub-task in mode: " + mode);
    return tool_result_t::ok(result);
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


tool_result_t handle_list_checkpoints(const json& /*params*/)
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
            "- /help — Show available commands\n"
            "- /clear — Clear the chat history\n"
            "- /mode <slug> — Switch to a mode\n"
            "- /checkpoint [message] — Save a checkpoint\n"
            "- /restore <id> — Restore a checkpoint\n"
            "- /skills — List available skills\n"
            "- /index — Rebuild the code index\n");
    }

    if (command == "clear") {
        g_chat_messages.clear();
        return tool_result_t::ok("Chat history cleared.");
    }

    if (command == "mode") {
        if (arguments.empty())
            return tool_result_t::error("Usage: /mode <slug>");
        json p;
        p["mode_slug"] = arguments;
        return handle_switch_mode(p);
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
    srv.register_tool({"switch_mode",
        "Switch the current operating mode. Available modes: agent, code, architect, ask, debug.",
        {{"mode_slug", "string", "The mode to switch to (e.g. 'code', 'architect', 'ask')", true},
         {"reason", "string", "Why you are switching modes", false}},
        false, handle_switch_mode});

    srv.register_tool({"new_task",
        "Create a new sub-task with a specific mode. Used for task delegation and orchestration.",
        {{"mode", "string", "The mode for the sub-task", true},
         {"message", "string", "The task description/message", true}},
        false, handle_new_task});

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
