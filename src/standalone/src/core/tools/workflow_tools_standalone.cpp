#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "mcp_standalone.hpp"
#include "../../helpers/diag_log.hpp"
#include "agent_registry.hpp"
#include "standalone_settings.hpp"
#include "standalone_chat.hpp"
#include "apply_diff.hpp"
#include "apply_patch.hpp"
#include "code_index.hpp"
#include "checkpoints.hpp"
#define AIDA_SKILLS_IMPLEMENTATION
#include "skills.hpp"
#include "tool_repetition.hpp"
#include "event_bus.hpp"
#include "session_store.hpp"
#include "auto_approval.hpp"
#include "command_sessions.hpp"

#include "../helpers/globals.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <mutex>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <system_error>
#include <utility>

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


std::string sanitize_workspace_path(const std::string& raw)
{
    std::string p = raw;
    for (char& c : p) { if (c == '/') c = '\\'; }

    if (!file_browser::current_dir.empty() && !p.empty() && p[0] != '\\' &&
        (p.size() < 2 || p[1] != ':'))
    {
        p = file_browser::current_dir + "\\" + p;
    }

    std::error_code ec;
    auto canonical = fs::weakly_canonical(fs::path(p), ec);
    if (ec) return raw;
    return canonical.string();
}


bool path_within_workspace(const std::string& canonical_path)
{
    if (file_browser::current_dir.empty())
        return true;

    std::error_code ec;
    auto ws = fs::weakly_canonical(fs::path(file_browser::current_dir), ec);
    if (ec) return false;

    auto ws_str = ws.string();
    auto p_str  = canonical_path;

    std::transform(ws_str.begin(), ws_str.end(), ws_str.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::transform(p_str.begin(), p_str.end(), p_str.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    return p_str.find(ws_str) == 0;
}

std::vector<code_index::search_result_t> direct_codebase_search(const std::string& query, const std::string& directory, int top_k)
{
    std::vector<code_index::search_result_t> results;
    if (query.empty())
        return results;
    std::string root = g_sa_settings.workspace.root_path.empty() ? file_browser::current_dir : g_sa_settings.workspace.root_path;
    if (root.empty())
        return results;

    std::error_code ec;
    fs::path root_path = fs::weakly_canonical(fs::path(root), ec);
    if (ec)
        root_path = fs::path(root);

    fs::path search_path = root_path;
    if (!directory.empty()) {
        fs::path dir_path(directory);
        if (dir_path.is_relative())
            dir_path = root_path / dir_path;
        std::error_code dir_ec;
        fs::path canonical_dir = fs::weakly_canonical(dir_path, dir_ec);
        if (!dir_ec)
            search_path = canonical_dir;
    }

    std::string root_lc = root_path.string();
    std::string search_lc = search_path.string();
    std::transform(root_lc.begin(), root_lc.end(), root_lc.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::transform(search_lc.begin(), search_lc.end(), search_lc.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (search_lc.find(root_lc) != 0)
        return results;

    std::string lower_query = query;
    std::transform(lower_query.begin(), lower_query.end(), lower_query.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    constexpr int max_files = 5000;
    int files_scanned = 0;
    for (auto it = fs::recursive_directory_iterator(search_path, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); ++it)
    {
        if (ec)
            break;
        if (static_cast<int>(results.size()) >= top_k)
            break;
        if (files_scanned >= max_files)
            break;
        std::error_code entry_ec;
        if (it->is_directory(entry_ec)) {
            std::string name = it->path().filename().string();
            if (name == ".git" || name == ".vs" || name == "node_modules" || name == "__pycache__")
                it.disable_recursion_pending();
            continue;
        }
        if (!it->is_regular_file(entry_ec))
            continue;
        std::string ext = it->path().extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (!code_index::is_indexable_extension(ext))
            continue;
        auto file_size = it->file_size(entry_ec);
        if (entry_ec || file_size > 2 * 1024 * 1024)
            continue;
        ++files_scanned;
        std::ifstream ifs(it->path(), std::ios::binary);
        if (!ifs.is_open())
            continue;
        std::string line;
        int line_number = 0;
        while (std::getline(ifs, line)) {
            ++line_number;
            std::string lower_line = line;
            std::transform(lower_line.begin(), lower_line.end(), lower_line.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (lower_line.find(lower_query) == std::string::npos)
                continue;
            code_index::search_result_t result;
            result.file_path = it->path().string();
            result.line_number = line_number;
            result.content = line.size() > 240 ? line.substr(0, 240) + "..." : line;
            result.score = 0.01;
            results.push_back(std::move(result));
            if (static_cast<int>(results.size()) >= top_k)
                break;
        }
    }
    diag::log_tagged_fmt("workflow",
        "codebase_search_direct root='%s' directory='%s' files=%d results=%zu query='%.80s'",
        root_path.string().c_str(),
        directory.c_str(),
        files_scanned,
        results.size(),
        query.c_str());
    return results;
}

tool_result_t codebase_results_response(const std::string& query, const std::vector<code_index::search_result_t>& results)
{
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


tool_result_t handle_switch_agent(const json& params)
{
    std::string name;
    if (params.contains("agent") && params["agent"].is_string())
        name = params["agent"].get<std::string>();
    else if (params.contains("name") && params["name"].is_string())
        name = params["name"].get<std::string>();
    else if (params.contains("agent_name") && params["agent_name"].is_string())
        name = params["agent_name"].get<std::string>();
    diag::log_tagged_fmt("workflow", "switch_agent entry name='%s'", name.c_str());
    if (name.empty())
    {
        diag::log_tagged_fmt("workflow", "switch_agent missing agent name");
        return tool_result_t::error("Missing required parameter: agent");
    }

    std::string reason;
    if (params.contains("reason") && params["reason"].is_string())
        reason = params["reason"].get<std::string>();

    const auto* info = aida::agent::get(name);
    if (info == nullptr)
    {
        diag::log_tagged_fmt("workflow", "switch_agent unknown agent='%s'", name.c_str());
        return tool_result_t::error("Unknown agent: " + name + ". Use list_agents to see available agents.");
    }

    std::string previous = aida::agent::active_agent_name();
    if (!aida::agent::set_active_agent(name))
    {
        diag::log_tagged_fmt("workflow", "switch_agent set_active failed err='%s'",
            aida::agent::last_error().c_str());
        return tool_result_t::error("Failed to switch agent: " + aida::agent::last_error());
    }

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

    diag::log_tagged_fmt("workflow", "switch_agent ok previous='%s' new='%s'",
        previous.c_str(), name.c_str());
    output_log::push(bottom_tab_t::output, "[agent] " + msg);
    return tool_result_t::ok(msg);
}


tool_result_t handle_plan_enter(const json&)
{
    diag::log_tagged_fmt("workflow", "plan_enter current='%s'",
        aida::agent::active_agent_name().c_str());
    if (aida::agent::active_agent_name() == "plan")
    {
        diag::log_tagged_fmt("workflow", "plan_enter already in plan mode");
        return tool_result_t::ok("Already in plan mode.");
    }

    std::string previous = aida::agent::active_agent_name();
    if (!aida::agent::set_active_agent("plan"))
    {
        diag::log_tagged_fmt("workflow", "plan_enter failed err='%s'",
            aida::agent::last_error().c_str());
        return tool_result_t::error("Failed to enter plan mode: " + aida::agent::last_error());
    }

    aida::events::agent_changed_t evt;
    evt.session_id = conversations::current_id;
    evt.previous_agent = previous;
    evt.new_agent = "plan";
    aida::events::publish(aida::events::event_agent_changed, evt);

    diag::log_tagged_fmt("workflow", "plan_enter ok previous='%s'", previous.c_str());
    output_log::push(bottom_tab_t::output, "[agent] Entered plan mode (previous: " + previous + ")");

    return tool_result_t::ok(
        "Entered plan mode. Edit/write/bash tools are now blocked. "
        "Use plan_exit when ready to execute.");
}


tool_result_t handle_plan_exit(const json& params)
{
    diag::log_tagged_fmt("workflow", "plan_exit entry current='%s'",
        aida::agent::active_agent_name().c_str());
    if (aida::agent::active_agent_name() != "plan")
    {
        diag::log_tagged_fmt("workflow", "plan_exit not in plan mode");
        return tool_result_t::error("Not in plan mode.");
    }

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

    diag::log_tagged_fmt("workflow", "plan_exit ok switched to build");
    return tool_result_t::ok("Plan complete. Switching to build agent to execute.");
}


tool_result_t handle_task(const json& params)
{
    std::string agent_name;
    if (params.contains("agent") && params["agent"].is_string())
        agent_name = params["agent"].get<std::string>();
    else if (params.contains("name") && params["name"].is_string())
        agent_name = params["name"].get<std::string>();
    diag::log_tagged_fmt("workflow", "task entry agent='%s'", agent_name.c_str());
    if (agent_name.empty())
    {
        diag::log_tagged_fmt("workflow", "task missing agent name");
        return tool_result_t::error("Missing required parameter: agent");
    }

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

    diag::log_tagged_fmt("workflow", "task spawning agent='%s' max_steps=%d",
        agent_name.c_str(), max_steps);
    output_log::push(bottom_tab_t::output, "[task] Spawning subagent: " + agent_name);

    std::string result;
    std::atomic<bool>* cancel_flag = chat_cancel_flag();
    bool ok = aida::agent::task::execute(agent_name, prompt, max_steps,
                                         parent_session_id, result, cancel_flag);
    if (!ok && result.empty())
    {
        diag::log_tagged_fmt("workflow", "task failed agent='%s' err='%s'",
            agent_name.c_str(), aida::agent::task::last_error().c_str());
        return tool_result_t::error("Subagent failed: " + aida::agent::task::last_error());
    }
    diag::log_tagged_fmt("workflow", "task ok agent='%s' result_len=%zu",
        agent_name.c_str(), result.size());
    return tool_result_t::ok(result);
}


tool_result_t handle_list_agents(const json&)
{
    diag::log_tagged_fmt("workflow", "list_agents entry");
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
    diag::log_tagged_fmt("workflow", "list_agents ok count=%zu", arr.size());
    return tool_result_t::ok(out, json{{"agents", arr}});
}


tool_result_t handle_ask_followup_question(const json& params)
{
    diag::log_tagged_fmt("workflow", "ask_followup_question entry");
    if (!params.contains("question") || !params["question"].is_string())
    {
        diag::log_tagged_fmt("workflow", "ask_followup_question missing question param");
        return tool_result_t::error("Missing required parameter: question");
    }

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

    diag::log_tagged_fmt("workflow", "ask_followup_question q='%.80s' options=%zu",
        question.c_str(), options.size());
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
    diag::log_tagged_fmt("workflow", "attempt_completion entry");
    if (!params.contains("result") || !params["result"].is_string())
    {
        diag::log_tagged_fmt("workflow", "attempt_completion missing result param");
        return tool_result_t::error("Missing required parameter: result");
    }

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

    diag::log_tagged_fmt("workflow", "attempt_completion result_len=%zu has_command=%d",
        result.size(), !command.empty() ? 1 : 0);
    std::string msg = "Task completion attempted.\nResult: " + result;
    if (!command.empty())
        msg += "\nVerification command: " + command;

    return tool_result_t::ok(msg);
}


tool_result_t handle_update_todo_list(const json& params)
{
    diag::log_tagged_fmt("workflow", "update_todo_list entry");
    if (!params.contains("content") || !params["content"].is_string())
    {
        diag::log_tagged_fmt("workflow", "update_todo_list missing content param");
        return tool_result_t::error("Missing required parameter: content");
    }

    std::string content = params["content"].get<std::string>();

    {
        std::lock_guard<std::mutex> lk(g_todo_mtx);
        g_task_todo = content;
    }

    const std::string sid = conversations::current_id;
    if (!sid.empty()) {
        (void)aida::session::set_session_todos(sid, content);
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

    diag::log_tagged_fmt("workflow", "update_todo_list ok done=%d total=%d", done, total);
    std::string msg = "Todo list updated. " + std::to_string(done) + "/" + std::to_string(total) + " items completed.";
    return tool_result_t::ok(msg);
}


tool_result_t handle_apply_diff(const json& params)
{
    diag::log_tagged_fmt("workflow", "apply_diff entry path='%s'",
        params.contains("path") && params["path"].is_string()
            ? params["path"].get<std::string>().c_str() : "");
    if (!params.contains("path") || !params["path"].is_string())
    {
        diag::log_tagged_fmt("workflow", "apply_diff missing path");
        return tool_result_t::error("Missing required parameter: path");
    }
    if (!params.contains("diff") || !params["diff"].is_string())
    {
        diag::log_tagged_fmt("workflow", "apply_diff missing diff");
        return tool_result_t::error("Missing required parameter: diff");
    }

    std::string path = sanitize_workspace_path(params["path"].get<std::string>());
    if (!path_within_workspace(path))
        return tool_result_t::error("Path is outside the workspace: " + path);

    std::string diff_text = params["diff"].get<std::string>();

    std::error_code exists_ec;
    if (!fs::exists(path, exists_ec) || exists_ec)
        return tool_result_t::error("File not found: " + path);

    std::ifstream ifs(path);
    if (!ifs)
        return tool_result_t::error("Cannot read file: " + path);

    std::string original((std::istreambuf_iterator<char>(ifs)),
                          std::istreambuf_iterator<char>());
    ifs.close();

    auto result = apply_diff::apply(original, diff_text);
    if (!result.success)
    {
        diag::log_tagged_fmt("workflow", "apply_diff failed path='%s' err='%s'",
            path.c_str(), result.error.c_str());
        return tool_result_t::error("Failed to apply diff: " + result.error);
    }

    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs)
        return tool_result_t::error("Cannot write file: " + path);

    ofs << result.content;
    ofs.close();

    std::string msg = "Applied diff to " + path + " successfully.";
    diag::log_tagged_fmt("workflow", "apply_diff ok path='%s'", path.c_str());
    output_log::push(bottom_tab_t::output, "[diff] " + msg);
    return tool_result_t::ok(msg);
}


tool_result_t handle_apply_patch(const json& params)
{
    diag::log_tagged_fmt("workflow", "apply_patch entry");
    if (!params.contains("patch") || !params["patch"].is_string())
    {
        diag::log_tagged_fmt("workflow", "apply_patch missing patch param");
        return tool_result_t::error("Missing required parameter: patch");
    }

    std::string patch_text = params["patch"].get<std::string>();

    auto parsed = apply_patch::parse(patch_text);
    if (parsed.empty())
        return tool_result_t::error("No valid file patches found in patch text.");

    for (const auto& fp : parsed) {
        std::string src = sanitize_workspace_path(fp.path);
        if (!path_within_workspace(src))
            return tool_result_t::error("Patch refers to a path outside the workspace: " + fp.path);
        if (fp.action == apply_patch::file_action_t::move_file) {
            std::string dst = sanitize_workspace_path(fp.move_to);
            if (!path_within_workspace(dst))
                return tool_result_t::error("Patch move destination outside workspace: " + fp.move_to);
        }
    }

    auto read_fn = [](const std::string& path) -> std::string {
        std::ifstream ifs(path);
        if (!ifs) return "";
        return std::string((std::istreambuf_iterator<char>(ifs)),
                            std::istreambuf_iterator<char>());
    };

    auto write_fn = [](const std::string& path, const std::string& content) -> bool {
        std::error_code ec;
        fs::create_directories(fs::path(path).parent_path(), ec);
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
        std::error_code ec;
        fs::create_directories(fs::path(to).parent_path(), ec);
        fs::rename(from, to, ec);
        return !ec;
    };

    auto result = apply_patch::apply(patch_text, read_fn, write_fn, delete_fn, move_fn);

    if (!result.success) {
        diag::log_tagged_fmt("workflow", "apply_patch failed err='%s'", result.error.c_str());
        return tool_result_t::error("Patch application failed: " + result.error);
    }

    int files_modified = static_cast<int>(result.modified_files.size());
    int files_deleted = static_cast<int>(result.deleted_files.size());
    int files_moved = static_cast<int>(result.moved_files.size());

    std::string msg = "Patch applied: " +
                     std::to_string(files_modified) + " modified, " +
                     std::to_string(files_deleted) + " deleted, " +
                     std::to_string(files_moved) + " moved.";
    diag::log_tagged_fmt("workflow", "apply_patch ok modified=%d deleted=%d moved=%d",
        files_modified, files_deleted, files_moved);
    output_log::push(bottom_tab_t::output, "[patch] " + msg);
    return tool_result_t::ok(msg);
}


tool_result_t handle_codebase_search(const json& params)
{
    diag::log_tagged_fmt("workflow", "codebase_search entry query='%.80s'",
        params.contains("query") && params["query"].is_string()
            ? params["query"].get<std::string>().c_str() : "");
    if (!params.contains("query") || !params["query"].is_string())
    {
        diag::log_tagged_fmt("workflow", "codebase_search missing query");
        return tool_result_t::error("Missing required parameter: query");
    }

    std::string query = params["query"].get<std::string>();
    std::string directory;
    if (params.contains("directory") && params["directory"].is_string())
        directory = params["directory"].get<std::string>();

    if (query.empty())
        return tool_result_t::error("Query cannot be empty.");

    std::unique_lock<std::mutex> lk(g_code_index_mtx);
    if (!g_code_index) {
        if (g_sa_settings.workspace.root_path.empty())
            return tool_result_t::error("No workspace is open. Open a workspace first.");

        g_code_index = std::make_unique<code_index::manager_t>(g_sa_settings.workspace.root_path);
        g_code_index->start_indexing();
        lk.unlock();
        auto direct = direct_codebase_search(query, directory, 10);
        if (!direct.empty())
            return codebase_results_response(query, direct);
        return tool_result_t::ok("Code index is being built. Please retry in a moment.");
    }

    if (g_code_index->state() == code_index::index_state_t::indexing) {
        auto partial_results = g_code_index->search(query, directory, 10);
        size_t indexed_count = g_code_index->indexed_count();
        lk.unlock();
        if (!partial_results.empty())
            return codebase_results_response(query, partial_results);
        auto direct = direct_codebase_search(query, directory, 10);
        if (!direct.empty())
            return codebase_results_response(query, direct);
        return tool_result_t::ok("Code index is still building. Please retry in a moment. " +
                                std::to_string(indexed_count) + " documents indexed so far.");
    }

    auto results = g_code_index->search(query, directory, 10);
    lk.unlock();
    diag::log_tagged_fmt("workflow", "codebase_search results=%zu query='%.80s'",
        results.size(), query.c_str());

    if (results.empty()) {
        auto direct = direct_codebase_search(query, directory, 10);
        if (!direct.empty())
            return codebase_results_response(query, direct);
        return tool_result_t::ok("No results found for query: " + query);
    }

    return codebase_results_response(query, results);
}


tool_result_t handle_read_command_output(const json& params)
{
    diag::log_tagged_fmt("workflow", "read_command_output entry id='%s'",
        params.contains("id") && params["id"].is_string()
            ? params["id"].get<std::string>().c_str() : "");
    if (!params.contains("id") || !params["id"].is_string())
    {
        diag::log_tagged_fmt("workflow", "read_command_output missing id");
        return tool_result_t::error("Missing required parameter: id");
    }

    std::string id = params["id"].get<std::string>();
    if (id.empty())
        return tool_result_t::error("Session id cannot be empty.");

    bool drop_after = false;
    if (params.contains("drop") && params["drop"].is_boolean())
        drop_after = params["drop"].get<bool>();

    size_t max_bytes = 65536;
    if (params.contains("max_bytes") && params["max_bytes"].is_number_integer()) {
        int v = params["max_bytes"].get<int>();
        if (v < 256) v = 256;
        if (v > 1048576) v = 1048576;
        max_bytes = static_cast<size_t>(v);
    }

    bool running = false;
    int64_t exit_code = 0;
    bool was_timeout = false;
    bool reader_done = false;
    int64_t duration_ms = 0;
    std::string sess_id;
    std::string sess_cmd;
    std::string out_copy;
    std::string err_copy;

    bool found = command_sessions::with_session(id,
        [&](command_sessions::command_session_t& sess) {
            sess_id = sess.id;
            sess_cmd = sess.command;
            running = sess.alive.load();
            reader_done = sess.reader_done.load(std::memory_order_acquire);
            exit_code = sess.exit_code.load();
            was_timeout = sess.timed_out.load();
            auto end = running ? std::chrono::steady_clock::now() : sess.finished_at;
            duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                end - sess.started_at).count();
            std::lock_guard<std::mutex> lk(sess.output_mutex);
            if (sess.stdout_buf.size() > max_bytes)
                out_copy.assign(sess.stdout_buf, sess.stdout_buf.size() - max_bytes, max_bytes);
            else
                out_copy = sess.stdout_buf;
            if (sess.stderr_buf.size() > max_bytes)
                err_copy.assign(sess.stderr_buf, sess.stderr_buf.size() - max_bytes, max_bytes);
            else
                err_copy = sess.stderr_buf;
        });

    if (!found)
    {
        diag::log_tagged_fmt("workflow", "read_command_output session not found id='%s'", id.c_str());
        return tool_result_t::error("Session not found: " + id);
    }

    diag::log_tagged_fmt("workflow", "read_command_output id='%s' running=%d exit=%lld",
        id.c_str(), (int)running, (long long)exit_code);
    json status;
    status["session_id"] = sess_id;
    status["command"] = sess_cmd;
    status["running"] = running;
    status["reader_done"] = reader_done;
    status["exit_code"] = running ? json(nullptr) : json(exit_code);
    status["timed_out"] = was_timeout;
    status["duration_ms"] = duration_ms;
    status["stdout"] = out_copy;
    status["stderr"] = err_copy;

    std::string text;
    text += "Session: " + sess_id + "\n";
    text += "Command: " + sess_cmd + "\n";
    text += running ? "Status: running\n" : ("Status: finished (exit=" + std::to_string(exit_code) + ")\n");
    if (was_timeout) text += "Timed out: yes\n";
    text += "Elapsed: " + std::to_string(duration_ms) + "ms\n";
    if (!out_copy.empty()) {
        text += "--- stdout ---\n";
        text += out_copy;
        if (out_copy.back() != '\n') text += "\n";
    }
    if (!err_copy.empty()) {
        text += "--- stderr ---\n";
        text += err_copy;
        if (err_copy.back() != '\n') text += "\n";
    }
    if (out_copy.empty() && err_copy.empty())
        text += "(no output yet)";

    if (drop_after && !running && reader_done)
        command_sessions::remove_session(id);

    return tool_result_t::ok(text, status);
}


tool_result_t handle_save_checkpoint(const json& params)
{
    diag::log_tagged_fmt("workflow", "save_checkpoint entry");
    std::string message;
    if (params.contains("message") && params["message"].is_string())
        message = params["message"].get<std::string>();

    std::lock_guard<std::mutex> lk(g_checkpoint_mtx);
    if (!g_checkpoint_svc) {
        if (g_sa_settings.workspace.root_path.empty())
            return tool_result_t::error("No workspace is open.");

        g_checkpoint_svc = std::make_unique<checkpoints::service_t>(
            g_sa_settings.workspace.root_path);

        char appdata[MAX_PATH] = {};
        DWORD appdata_len = GetEnvironmentVariableA("APPDATA", appdata, MAX_PATH);
        std::string checkpoint_dir;
        if (appdata_len > 0 && appdata_len < MAX_PATH) {
            checkpoint_dir = std::string(appdata) + "\\AiDA\\Standalone\\checkpoints";
        } else {
            checkpoint_dir = g_sa_settings.workspace.root_path + "\\.aida\\checkpoints";
        }
        g_checkpoint_svc->set_storage_dir(checkpoint_dir);
    }

    std::vector<std::string> tracked;
    bool ok = g_checkpoint_svc->save_checkpoint(g_task_id, message, 0, tracked);
    if (!ok)
    {
        diag::log_tagged_fmt("workflow", "save_checkpoint failed");
        return tool_result_t::error("Failed to save checkpoint.");
    }

    diag::log_tagged_fmt("workflow", "save_checkpoint ok msg='%.80s'", message.c_str());
    return tool_result_t::ok("Checkpoint saved." +
                            (message.empty() ? std::string{} : " (" + message + ")"));
}


tool_result_t handle_restore_checkpoint(const json& params)
{
    diag::log_tagged_fmt("workflow", "restore_checkpoint entry id='%s'",
        params.contains("checkpoint_id") && params["checkpoint_id"].is_string()
            ? params["checkpoint_id"].get<std::string>().c_str() : "");
    if (!params.contains("checkpoint_id") || !params["checkpoint_id"].is_string())
    {
        diag::log_tagged_fmt("workflow", "restore_checkpoint missing id");
        return tool_result_t::error("Missing required parameter: checkpoint_id");
    }

    std::string id = params["checkpoint_id"].get<std::string>();

    std::lock_guard<std::mutex> lk(g_checkpoint_mtx);
    if (!g_checkpoint_svc)
        return tool_result_t::error("No checkpoints available. Save a checkpoint first.");

    bool ok = g_checkpoint_svc->restore_checkpoint(g_task_id, id);
    if (!ok)
    {
        diag::log_tagged_fmt("workflow", "restore_checkpoint failed id='%s'", id.c_str());
        return tool_result_t::error("Failed to restore checkpoint: " + id);
    }

    diag::log_tagged_fmt("workflow", "restore_checkpoint ok id='%s'", id.c_str());
    return tool_result_t::ok("Checkpoint " + id + " restored successfully.");
}


tool_result_t handle_list_checkpoints(const json& )
{
    diag::log_tagged_fmt("workflow", "list_checkpoints entry");
    std::lock_guard<std::mutex> lk(g_checkpoint_mtx);
    if (!g_checkpoint_svc)
    {
        diag::log_tagged_fmt("workflow", "list_checkpoints no svc");
        return tool_result_t::ok("No checkpoints available.");
    }

    auto cps = g_checkpoint_svc->list_checkpoints(g_task_id);
    diag::log_tagged_fmt("workflow", "list_checkpoints count=%zu", cps.size());
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
    diag::log_tagged_fmt("workflow", "skill entry name='%s'",
        params.contains("name") && params["name"].is_string()
            ? params["name"].get<std::string>().c_str() : "");
    if (!params.contains("name") || !params["name"].is_string())
    {
        diag::log_tagged_fmt("workflow", "skill missing name param");
        return tool_result_t::error("Missing required parameter: name");
    }

    std::string name = params["name"].get<std::string>();
    std::string arguments;
    if (params.contains("arguments") && params["arguments"].is_string())
        arguments = params["arguments"].get<std::string>();

    std::lock_guard<std::mutex> lk(g_skills_mtx);
    if (!g_skills_mgr) {
        std::string workspace = g_sa_settings.workspace.root_path;
        if (workspace.empty())
            return tool_result_t::error("No workspace is open.");

        char appdata[MAX_PATH] = {};
        DWORD appdata_len = GetEnvironmentVariableA("APPDATA", appdata, MAX_PATH);

        g_skills_mgr = std::make_unique<skills::manager_t>();
        g_skills_mgr->add_search_path(workspace + "/.aida/skills");
        if (appdata_len > 0 && appdata_len < MAX_PATH) {
            g_skills_mgr->add_search_path(std::string(appdata) + "\\AiDA\\Standalone\\skills");
        }
        g_skills_mgr->discover();
    }

    if (!g_skills_mgr->has_skill(name))
    {
        diag::log_tagged_fmt("workflow", "skill not found name='%s'", name.c_str());
        return tool_result_t::error("Skill not found: " + name);
    }

    diag::log_tagged_fmt("workflow", "skill resolving name='%s'", name.c_str());
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
    diag::log_tagged_fmt("workflow", "run_slash_command entry cmd='%s'",
        params.contains("command") && params["command"].is_string()
            ? params["command"].get<std::string>().c_str() : "");
    if (!params.contains("command") || !params["command"].is_string())
    {
        diag::log_tagged_fmt("workflow", "run_slash_command missing command param");
        return tool_result_t::error("Missing required parameter: command");
    }

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

    diag::log_tagged_fmt("workflow", "run_slash_command unknown cmd='%s'", command.c_str());
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
    diag::log_tagged_fmt("workflow", "initialize_code_index root='%s'", workspace_root.c_str());
    std::lock_guard<std::mutex> lk(g_code_index_mtx);
    if (!g_code_index) {
        g_code_index = std::make_unique<code_index::manager_t>(workspace_root);
        g_code_index->start_indexing();
        diag::log_tagged_fmt("workflow", "initialize_code_index started indexing");
    } else {
        diag::log_tagged_fmt("workflow", "initialize_code_index already initialized");
    }
}

void shutdown_services()
{
    diag::log_tagged_fmt("workflow", "shutdown_services entry");
    {
        std::lock_guard<std::mutex> lk(g_code_index_mtx);
        if (g_code_index) {
            diag::log_tagged_fmt("workflow", "shutdown_services stopping code index");
            g_code_index->stop_indexing();
            g_code_index.reset();
        }
    }
    {
        std::lock_guard<std::mutex> lk(g_checkpoint_mtx);
        if (g_checkpoint_svc) {
            diag::log_tagged_fmt("workflow", "shutdown_services resetting checkpoint svc");
            g_checkpoint_svc.reset();
        }
    }
    {
        std::lock_guard<std::mutex> lk(g_skills_mtx);
        if (g_skills_mgr) {
            diag::log_tagged_fmt("workflow", "shutdown_services resetting skills mgr");
            g_skills_mgr.reset();
        }
    }
    diag::log_tagged_fmt("workflow", "shutdown_services done");
}


void register_workflow_tools(mcp_standalone::server_t& srv)
{
    diag::log_tagged_fmt("workflow", "register_workflow_tools entry");
    srv.register_tool({"switch_agent",
        "Switch the current operating agent. Built-in primary agents: build (default), plan. "
        "Subagents (build/plan only) cannot be activated as primary.",
        {{"agent", "string", "Agent name (e.g. 'build', 'plan')", true},
         {"reason", "string", "Why you are switching agents", false}},
        false, handle_switch_agent,
        mcp_standalone::tool_visibility_t::internal_only});

    srv.register_tool({"plan_enter",
        "Enter PLAN mode. Use this when the user's request would benefit from planning before "
        "implementation. Plan mode is read-only: edit/write/bash and other mutation tools become "
        "hard-denied. Once a plan is ready, call plan_exit to switch to the build agent. Call this "
        "tool when: the user explicitly asks for a plan; the request is complex enough to benefit "
        "from research and design first; the task involves multiple files or architectural decisions. "
        "Do NOT call for trivial single-step tasks or when the user has asked for immediate execution.",
        {},
        true, handle_plan_enter,
        mcp_standalone::tool_visibility_t::internal_only});

    srv.register_tool({"plan_exit",
        "Exit PLAN mode and switch to the build agent so the plan can be executed. Inserts a "
        "synthetic user handoff message into the session, then switches to the build agent. "
        "Call this only after the plan is fully written, all clarifying questions are answered, "
        "and the user has confirmed (explicitly or implicitly) they are ready to execute.",
        {{"summary", "string", "Optional one-paragraph plan summary that will be attached to the handoff message.", false}},
        false, handle_plan_exit,
        mcp_standalone::tool_visibility_t::internal_only});

    srv.register_tool({"task",
        "Spawn a subagent in an isolated context to perform a focused task and return its final result. "
        "Available subagents: 'general' (multi-step research), 'explore' (read-only file/binary search). "
        "The subagent runs concurrently with its own LLM client and tool stack.",
        {{"agent", "string", "Subagent name ('general' or 'explore')", true},
         {"prompt", "string", "The task description / instructions for the subagent", true},
         {"max_steps", "number", "Maximum tool-use turns the subagent may take (default 16, max 64)", false}},
        false, handle_task,
        mcp_standalone::tool_visibility_t::internal_only});

    srv.register_tool({"list_agents",
        "List all registered agents (primary and subagent), including custom user-defined ones.",
        {}, true, handle_list_agents,
        mcp_standalone::tool_visibility_t::internal_only});

    srv.register_tool({"ask_followup_question",
        "Ask the user a clarifying question. Use this when you need more information before proceeding.",
        {{"question", "string", "The question to ask the user", true},
         {"options", "array", "Optional list of suggested answers", false}},
        true, handle_ask_followup_question,
        mcp_standalone::tool_visibility_t::internal_only});

    srv.register_tool({"attempt_completion",
        "Signal that you believe the task is complete. Present your result to the user for approval.",
        {{"result", "string", "A summary of what was accomplished", true},
         {"command", "string", "An optional command the user can run to verify", false}},
        true, handle_attempt_completion,
        mcp_standalone::tool_visibility_t::internal_only});

    srv.register_tool({"update_todo_list",
        "Update the task's todo list. Use markdown checkbox format: - [ ] item or - [x] done item.",
        {{"content", "string", "The full todo list in markdown format", true}},
        true, handle_update_todo_list,
        mcp_standalone::tool_visibility_t::internal_only});

    srv.register_tool({"apply_diff",
        "Apply a unified diff to a file. Use standard unified diff format with @@ hunks.",
        {{"path", "string", "Path to the file to modify", true},
         {"diff", "string", "The unified diff content to apply", true}},
        false, handle_apply_diff,
        mcp_standalone::tool_visibility_t::internal_only});

    srv.register_tool({"apply_patch",
        "Apply a multi-file patch in Codex format. Supports adding, deleting, updating, and moving files.",
        {{"patch", "string", "The patch content in *** Begin Patch / *** End Patch format", true}},
        false, handle_apply_patch,
        mcp_standalone::tool_visibility_t::internal_only});

    srv.register_tool({"codebase_search",
        "Search the codebase for semantically relevant code. Returns matching code with file paths and line numbers.",
        {{"query", "string", "The search query describing what you're looking for", true},
         {"directory", "string", "Optional directory prefix to scope the search", false}},
        true, handle_codebase_search,
        mcp_standalone::tool_visibility_t::internal_only});

    srv.register_tool({"read_command_output",
        "Read output from a previously started background command by its terminal session id. "
        "Returns the most recent stdout/stderr (up to max_bytes), running state, exit code if "
        "finished, and elapsed time. If drop=true and the session has finished, the session is "
        "removed from the registry after this call.",
        {{"id",        "string",  "The terminal session id to read output from.", true},
         {"max_bytes", "integer", "Cap on returned bytes per stream (256-1048576). Default: 65536.", false},
         {"drop",      "boolean", "Drop the session from the registry after reading (only if finished). Default: false.", false}},
        true, handle_read_command_output,
        mcp_standalone::tool_visibility_t::internal_only});

    srv.register_tool({"save_checkpoint",
        "Save a checkpoint of the current workspace state. Use before making significant changes.",
        {{"message", "string", "Optional description for this checkpoint", false}},
        false, handle_save_checkpoint,
        mcp_standalone::tool_visibility_t::internal_only});

    srv.register_tool({"restore_checkpoint",
        "Restore the workspace to a previously saved checkpoint.",
        {{"checkpoint_id", "string", "The ID of the checkpoint to restore", true}},
        false, handle_restore_checkpoint,
        mcp_standalone::tool_visibility_t::internal_only});

    srv.register_tool({"list_checkpoints",
        "List all saved checkpoints for the current workspace.",
        {}, true, handle_list_checkpoints,
        mcp_standalone::tool_visibility_t::internal_only});

    srv.register_tool({"skill",
        "Invoke a registered skill by name. Skills provide specialized instructions for specific tasks.",
        {{"name", "string", "The name of the skill to invoke", true},
         {"arguments", "string", "Optional arguments to pass to the skill", false}},
        true, handle_skill,
        mcp_standalone::tool_visibility_t::internal_only});

    srv.register_tool({"run_slash_command",
        "Execute a slash command. Available: /help, /clear, /agent <name>, /agents, /checkpoint [message], /restore <id>, /skills, /index.",
        {{"command", "string", "The command name (without the leading /)", true},
         {"arguments", "string", "Optional arguments for the command", false}},
        false, handle_run_slash_command,
        mcp_standalone::tool_visibility_t::internal_only});

    diag::log_tagged_fmt("workflow", "register_workflow_tools tools registered");
    static aida::events::subscription_handle_t s_session_selected_sub;
    if (!s_session_selected_sub.valid()) {
        s_session_selected_sub = aida::events::subscribe(
            aida::events::event_session_selected,
            std::function<void(const aida::events::session_selected_t&)>(
                [](const aida::events::session_selected_t& ev) {
                    if (ev.session_id.empty()) return;

                    std::string todos;
                    if (aida::session::get_session_todos(ev.session_id, todos)) {
                        std::lock_guard<std::mutex> lk(g_todo_mtx);
                        g_task_todo = todos;
                    }

                    (void)auto_approval::load_session_rules_from_store(ev.session_id);
                }));
    }
}

}
