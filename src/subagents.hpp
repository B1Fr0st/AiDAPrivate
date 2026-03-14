#pragma once

#include <cctype>
#include <deque>
#include <filesystem>

#include "aida_pro.hpp"
#include "agentic.hpp"
#include "ai_client.hpp"

namespace subagents
{

using json = nlohmann::json;

enum class session_state_t
{
    accepted,
    queued,
    running,
    completed,
    failed,
    timed_out,
    cancelled,
    archived
};

struct spawn_request_t
{
    std::string task;
    std::string label;
    std::string agent_id;
    std::string model;
    std::string thinking;
    int run_timeout_seconds = 0;
    bool thread = false;
    std::string mode = "run";
    std::string cleanup = "keep";
    std::string sandbox = "inherit";
};

struct log_entry_t
{
    uint64_t timestamp_ms = 0;
    std::string type;
    std::string message;
    json data;
};

struct steering_message_t
{
    uint64_t timestamp_ms = 0;
    std::string message;
};

struct session_record_t : public std::enable_shared_from_this<session_record_t>
{
    std::string session_key;
    std::string session_id;
    std::string label;
    std::string task;
    std::string agent_id;
    std::string requester_session_key;
    uint64_t requester_run_id = 0;
    int depth = 0;
    bool allow_session_tools = false;
    bool allow_spawn_children = false;
    std::string model;
    std::string thinking;
    std::string mode = "run";
    std::string cleanup = "keep";
    std::string sandbox = "inherit";
    bool thread_requested = false;
    int run_timeout_seconds = 0;

    std::atomic<session_state_t> state{session_state_t::accepted};
    std::atomic<bool> cancel_requested{false};
    std::atomic<uint64_t> created_at_ms{0};
    std::atomic<uint64_t> started_at_ms{0};
    std::atomic<uint64_t> completed_at_ms{0};
    std::atomic<size_t> input_tokens{0};
    std::atomic<size_t> output_tokens{0};
    std::atomic<size_t> total_tokens{0};

    std::string assigned_user_message;
    std::string assigned_context_block;
    std::string assigned_chat_history;
    std::string final_result;
    std::string error_message;
    std::string transcript_path;
    bool archived = false;

    mutable std::mutex mutex;
    std::vector<std::string> child_session_keys;
    std::vector<log_entry_t> log_entries;
    std::deque<steering_message_t> steering_messages;
    std::function<void()> cancel_callback;
};

struct thread_context_t
{
    std::shared_ptr<session_record_t> session;
    uint64_t run_id = 0;
};

inline thread_local thread_context_t g_thread_context;

template <typename Fn>
class scope_exit_t
{
public:
    explicit scope_exit_t(Fn fn) : _fn(std::move(fn)) {}
    ~scope_exit_t() { _fn(); }

    scope_exit_t(const scope_exit_t&) = delete;
    scope_exit_t& operator=(const scope_exit_t&) = delete;

private:
    Fn _fn;
};

inline uint64_t now_ms()
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

inline std::string trim_copy(const std::string& value)
{
    qstring qv = value.c_str();
    qv.trim2();
    return qv.c_str();
}

inline std::string lower_copy(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

inline std::string state_to_string(session_state_t state)
{
    switch (state)
    {
        case session_state_t::accepted:  return "accepted";
        case session_state_t::queued:    return "queued";
        case session_state_t::running:   return "running";
        case session_state_t::completed: return "completed";
        case session_state_t::failed:    return "failed";
        case session_state_t::timed_out: return "timed_out";
        case session_state_t::cancelled: return "cancelled";
        case session_state_t::archived:  return "archived";
    }
    return "unknown";
}

inline bool is_session_tool_name(const std::string& tool_name)
{
    static const std::unordered_set<std::string> session_tools = {
        "sessions_spawn",
        "sessions_list",
        "sessions_history",
        "sessions_send",
        "subagents"
    };
    return session_tools.find(tool_name) != session_tools.end();
}

inline std::filesystem::path transcript_root_dir()
{
    std::filesystem::path root(get_user_idadir());
    root /= "aida_subagents";
    std::error_code ec;
    std::filesystem::create_directories(root, ec);
    return root;
}

inline std::string make_session_id(uint64_t seed)
{
    std::ostringstream ss;
    ss << std::hex << seed;
    return ss.str();
}

inline std::string truncate_text(const std::string& value, size_t max_chars)
{
    if (value.size() <= max_chars)
        return value;
    if (max_chars < 16)
        return value.substr(0, max_chars);
    return value.substr(0, max_chars) + "\n... (truncated)";
}

inline std::string current_agent_id()
{
    return "aida";
}

class manager_t
{
public:
    static manager_t& instance()
    {
        static manager_t mgr;
        return mgr;
    }

    std::shared_ptr<session_record_t> get_or_create_root_session()
    {
        std::lock_guard<std::mutex> lock(_mutex);
        return get_or_create_root_session_locked();
    }

    uint64_t begin_run_for_current_session(
        const std::string& user_message,
        const std::string& context_block,
        const std::string& chat_history)
    {
        if (!g_thread_context.session)
            g_thread_context.session = get_or_create_root_session();

        std::lock_guard<std::mutex> lock(_mutex);
        auto session = g_thread_context.session;
        const uint64_t run_id = ++_next_run_ids[session->session_key];
        g_thread_context.run_id = run_id;

        session->assigned_user_message = sanitize_utf8(user_message);
        session->assigned_context_block = sanitize_utf8(context_block);
        session->assigned_chat_history = sanitize_utf8(chat_history);

        append_log_locked(session, "run_begin",
            "Starting agent run #" + std::to_string(run_id),
            json{{"run_id", run_id}});
        return run_id;
    }

    void end_run_for_current_session()
    {
        if (!g_thread_context.session || g_thread_context.run_id == 0)
            return;

        std::lock_guard<std::mutex> lock(_mutex);
        append_log_locked(g_thread_context.session, "run_end",
            "Ending agent run #" + std::to_string(g_thread_context.run_id),
            json{{"run_id", g_thread_context.run_id}});
        g_thread_context.run_id = 0;
    }

    bool has_current_session() const
    {
        return g_thread_context.session != nullptr;
    }

    std::string current_session_key() const
    {
        return g_thread_context.session ? g_thread_context.session->session_key : std::string();
    }

    uint64_t current_run_id() const
    {
        return g_thread_context.run_id;
    }

    bool current_session_allows_session_tools() const
    {
        if (!g_thread_context.session)
            return true;
        return g_thread_context.session->allow_session_tools;
    }

    bool can_execute_tool(const std::string& tool_name) const
    {
        if (!is_session_tool_name(tool_name))
            return true;
        return current_session_allows_session_tools();
    }

    bool is_tool_visible(const std::string& tool_name) const
    {
        return can_execute_tool(tool_name);
    }

    std::string session_prompt_guidance() const
    {
        if (!g_thread_context.session)
        {
            return
                "Sub-agent tools are available. Use `sessions_spawn` for independent or slow branches that can run in parallel.\n"
                "`sessions_spawn` is non-blocking: it returns immediately with a run id and child session key.\n"
                "Child completions are announced back automatically in later rounds. Use `subagents` or `sessions_history` only when you need to inspect, steer, or cancel a child explicitly.\n";
        }

        if (!g_thread_context.session->allow_session_tools)
        {
            return
                "You are running as a leaf sub-agent in an isolated session.\n"
                "Focus only on the assigned task, use the tools you already have, and return concise, evidence-backed findings for the parent agent.\n"
                "Do not address the end user directly and do not ask for more session control tools.\n";
        }

        return
            "You are running as an orchestrator-capable sub-agent.\n"
            "You may use `sessions_spawn` to fan out independent branches, but keep the fan-out focused and bounded.\n"
            "Use `subagents`, `sessions_list`, and `sessions_history` to monitor or synthesize child results.\n";
    }

    int current_depth() const
    {
        return g_thread_context.session ? g_thread_context.session->depth : 0;
    }

    int current_active_child_count() const
    {
        if (!g_thread_context.session)
            return 0;

        std::lock_guard<std::mutex> lock(_mutex);
        return active_child_count_locked(g_thread_context.session->session_key);
    }

    std::vector<std::string> take_runtime_updates_for_current_run()
    {
        std::vector<std::string> blocks;
        if (!g_thread_context.session || g_thread_context.run_id == 0)
            return blocks;

        std::lock_guard<std::mutex> lock(_mutex);
        auto ann_it = _pending_announcements.find(g_thread_context.session->session_key);
        if (ann_it != _pending_announcements.end())
        {
            auto run_it = ann_it->second.find(g_thread_context.run_id);
            if (run_it != ann_it->second.end())
            {
                while (!run_it->second.empty())
                {
                    blocks.push_back(run_it->second.front());
                    run_it->second.pop_front();
                }
                if (run_it->second.empty())
                    ann_it->second.erase(run_it);
            }
        }

        auto& steering = g_thread_context.session->steering_messages;
        while (!steering.empty())
        {
            const steering_message_t msg = steering.front();
            steering.pop_front();
            std::ostringstream ss;
            ss << "### Steering Update\n"
               << msg.message << "\n";
            blocks.push_back(ss.str());
        }

        return blocks;
    }

    bool wait_for_update_for_current_run(int timeout_ms)
    {
        if (!g_thread_context.session || g_thread_context.run_id == 0)
            return false;

        std::unique_lock<std::mutex> lock(_mutex);
        const std::string session_key = g_thread_context.session->session_key;
        const uint64_t run_id = g_thread_context.run_id;
        return _update_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&]() {
            auto ann_it = _pending_announcements.find(session_key);
            if (ann_it != _pending_announcements.end())
            {
                auto run_it = ann_it->second.find(run_id);
                if (run_it != ann_it->second.end() && !run_it->second.empty())
                    return true;
            }
            return !g_thread_context.session->steering_messages.empty();
        });
    }

    json spawn(const spawn_request_t& request)
    {
        if (!g_thread_context.session || g_thread_context.run_id == 0)
        {
            return json{{"status", "error"}, {"message", "sessions_spawn is only available while an agent run is active."}};
        }

        const std::string normalized_mode = request.mode.empty() ? "run" : lower_copy(request.mode);
        const std::string normalized_cleanup = request.cleanup.empty() ? "keep" : lower_copy(request.cleanup);
        const std::string normalized_sandbox = request.sandbox.empty() ? "inherit" : lower_copy(request.sandbox);

        std::lock_guard<std::mutex> lock(_mutex);
        archive_expired_sessions_locked();

        auto parent = g_thread_context.session;
        if (!parent->allow_spawn_children)
        {
            return json{{"status", "error"}, {"message", "This session cannot spawn child sub-agents at the current depth."}};
        }

        const int next_depth = parent->depth + 1;
        if (next_depth > _max_spawn_depth)
        {
            return json{{"status", "error"}, {"message", "Sub-agent spawn depth exceeded."}};
        }

        if (active_child_count_locked(parent->session_key) >= _max_children_per_agent)
        {
            return json{{"status", "error"}, {"message", "Per-agent active child limit reached."}};
        }

        const uint64_t numeric_id = ++_session_counter;
        auto child = std::make_shared<session_record_t>();
        child->session_id = make_session_id(numeric_id);
        child->session_key = make_child_session_key_locked(parent, child->session_id);
        child->label = request.label.empty() ? ("subagent-" + child->session_id) : sanitize_utf8(request.label);
        child->task = sanitize_utf8(request.task);
        child->agent_id = request.agent_id.empty() ? current_agent_id() : sanitize_utf8(request.agent_id);
        child->requester_session_key = parent->session_key;
        child->requester_run_id = g_thread_context.run_id;
        child->depth = next_depth;
        child->allow_session_tools = (_max_spawn_depth >= 2 && next_depth == 1);
        child->allow_spawn_children = (next_depth < _max_spawn_depth);
        child->model = sanitize_utf8(request.model);
        child->thinking = sanitize_utf8(request.thinking);
        child->run_timeout_seconds = request.run_timeout_seconds > 0
            ? request.run_timeout_seconds
            : _default_run_timeout_seconds;
        child->thread_requested = request.thread;
        child->mode = normalized_mode;
        child->cleanup = normalized_cleanup == "delete" ? "delete" : "keep";
        child->sandbox = normalized_sandbox;
        child->created_at_ms = now_ms();
        child->assigned_user_message = child->task;
        child->assigned_context_block = build_child_context_locked(parent, *child);
        child->assigned_chat_history = truncate_text(parent->assigned_chat_history, 24000);
        child->transcript_path = make_transcript_path_locked(child->session_id);

        _sessions_by_key[child->session_key] = child;
        _session_key_by_id[child->session_id] = child->session_key;
        parent->child_session_keys.push_back(child->session_key);

        append_log_locked(parent, "spawn",
            "Spawned sub-agent `" + child->label + "`",
            json{{"child_session_key", child->session_key}, {"child_session_id", child->session_id}, {"task", truncate_text(child->task, 512)}});
        append_log_locked(child, "spawned",
            "Accepted sub-agent task.",
            json{{"requester_session_key", child->requester_session_key}, {"requester_run_id", child->requester_run_id}, {"task", truncate_text(child->task, 1024)}});

        std::thread([this, child, settings_snapshot = g_settings]() mutable {
            run_subagent_session(child, settings_snapshot);
        }).detach();

        return json{
            {"status", "accepted"},
            {"runId", child->session_id},
            {"childSessionKey", child->session_key},
            {"label", child->label},
            {"depth", child->depth},
            {"mode", child->mode}
        };
    }

    json list_visible_sessions() const
    {
        std::lock_guard<std::mutex> lock(_mutex);
        json items = json::array();
        const std::string anchor = g_thread_context.session
            ? g_thread_context.session->session_key
            : std::string("agent:") + current_agent_id() + ":main";

        for (const auto& [key, session] : _sessions_by_key)
        {
            if (!is_visible_from_locked(anchor, key))
                continue;
            items.push_back(build_session_summary_locked(session));
        }

        return items;
    }

    json get_session_info(const std::string& id_or_key, size_t log_limit, bool include_log) const
    {
        std::lock_guard<std::mutex> lock(_mutex);
        auto session = resolve_visible_session_locked(id_or_key);
        if (!session)
            return json{{"status", "error"}, {"message", "Unknown or inaccessible sub-agent session."}};

        json info = build_session_summary_locked(session);
        info["task"] = session->task;
        info["result"] = truncate_text(session->final_result, 12000);
        if (!session->error_message.empty())
            info["error"] = session->error_message;
        info["transcriptPath"] = session->transcript_path;

        if (include_log)
            info["log"] = build_log_array_locked(session, log_limit == 0 ? 200 : log_limit);
        return info;
    }

    json get_session_history(const std::string& id_or_key, size_t limit) const
    {
        std::lock_guard<std::mutex> lock(_mutex);
        auto session = resolve_visible_session_locked(id_or_key);
        if (!session)
            return json{{"status", "error"}, {"message", "Unknown or inaccessible sub-agent session."}};

        return json{
            {"session", build_session_summary_locked(session)},
            {"history", build_log_array_locked(session, limit == 0 ? 200 : limit)}
        };
    }

    json send_message(const std::string& id_or_key, const std::string& message, bool steer)
    {
        std::lock_guard<std::mutex> lock(_mutex);
        auto session = resolve_visible_session_locked(id_or_key);
        if (!session)
            return json{{"status", "error"}, {"message", "Unknown or inaccessible sub-agent session."}};

        const session_state_t state = session->state.load();
        if (state == session_state_t::completed || state == session_state_t::failed
            || state == session_state_t::timed_out || state == session_state_t::cancelled
            || state == session_state_t::archived)
        {
            return json{{"status", "error"}, {"message", "Cannot send to a completed sub-agent session."}};
        }

        steering_message_t msg;
        msg.timestamp_ms = now_ms();
        msg.message = sanitize_utf8(message);
        session->steering_messages.push_back(msg);
        append_log_locked(session, steer ? "steer" : "send", msg.message, json::object());
        _update_cv.notify_all();

        return json{{"status", "accepted"}, {"session", session->session_key}, {"message", msg.message}};
    }

    json kill(const std::string& id_or_key, bool cascade)
    {
        std::lock_guard<std::mutex> lock(_mutex);
        auto session = resolve_visible_session_locked(id_or_key);
        if (!session)
            return json{{"status", "error"}, {"message", "Unknown or inaccessible sub-agent session."}};

        size_t affected = 0;
        request_cancel_locked(session, cascade, &affected);
        return json{{"status", "accepted"}, {"cancelled", static_cast<uint64_t>(affected)}, {"session", session->session_key}};
    }

    json kill_all_visible(bool cascade)
    {
        std::lock_guard<std::mutex> lock(_mutex);
        const std::string anchor = g_thread_context.session
            ? g_thread_context.session->session_key
            : std::string("agent:") + current_agent_id() + ":main";

        size_t affected = 0;
        for (const auto& [key, session] : _sessions_by_key)
        {
            if (key == anchor)
                continue;
            if (!is_visible_from_locked(anchor, key))
                continue;
            request_cancel_locked(session, cascade, &affected);
        }

        return json{{"status", "accepted"}, {"cancelled", static_cast<uint64_t>(affected)}};
    }

private:
    manager_t() = default;

    std::shared_ptr<session_record_t> get_or_create_root_session_locked()
    {
        const std::string root_key = std::string("agent:") + current_agent_id() + ":main";
        auto it = _sessions_by_key.find(root_key);
        if (it != _sessions_by_key.end())
            return it->second;

        auto root = std::make_shared<session_record_t>();
        root->session_key = root_key;
        root->session_id = "main";
        root->label = "main";
        root->task = "Main AiDA session";
        root->agent_id = current_agent_id();
        root->depth = 0;
        root->allow_session_tools = true;
        root->allow_spawn_children = true;
        root->mode = "session";
        root->created_at_ms = now_ms();
        root->transcript_path = make_transcript_path_locked(root->session_id);

        _sessions_by_key[root_key] = root;
        _session_key_by_id[root->session_id] = root->session_key;
        append_log_locked(root, "session_created", "Created root agent session.", json::object());
        return root;
    }

    std::string make_transcript_path_locked(const std::string& session_id) const
    {
        std::filesystem::path path = transcript_root_dir() / (session_id + ".jsonl");
        return path.string();
    }

    std::string make_child_session_key_locked(const std::shared_ptr<session_record_t>& parent, const std::string& child_id) const
    {
        if (parent->depth == 0)
            return std::string("agent:") + current_agent_id() + ":subagent:" + child_id;
        return parent->session_key + ":subagent:" + child_id;
    }

    int active_child_count_locked(const std::string& parent_session_key) const
    {
        int count = 0;
        for (const auto& [_, session] : _sessions_by_key)
        {
            if (session->requester_session_key != parent_session_key)
                continue;
            const session_state_t state = session->state.load();
            if (state == session_state_t::accepted || state == session_state_t::queued || state == session_state_t::running)
                ++count;
        }
        return count;
    }

    bool is_visible_from_locked(const std::string& anchor_session_key, const std::string& candidate_session_key) const
    {
        if (anchor_session_key == candidate_session_key)
            return true;

        auto it = _sessions_by_key.find(candidate_session_key);
        while (it != _sessions_by_key.end() && it->second)
        {
            const auto& requester = it->second->requester_session_key;
            if (requester.empty())
                return false;
            if (requester == anchor_session_key)
                return true;
            it = _sessions_by_key.find(requester);
        }
        return false;
    }

    std::shared_ptr<session_record_t> resolve_visible_session_locked(const std::string& id_or_key) const
    {
        std::string key = id_or_key;
        auto id_it = _session_key_by_id.find(id_or_key);
        if (id_it != _session_key_by_id.end())
            key = id_it->second;

        auto it = _sessions_by_key.find(key);
        if (it == _sessions_by_key.end())
            return nullptr;

        const std::string anchor = g_thread_context.session
            ? g_thread_context.session->session_key
            : std::string("agent:") + current_agent_id() + ":main";
        return is_visible_from_locked(anchor, key) ? it->second : nullptr;
    }

    json build_session_summary_locked(const std::shared_ptr<session_record_t>& session) const
    {
        return json{
            {"sessionKey", session->session_key},
            {"sessionId", session->session_id},
            {"label", session->label},
            {"status", state_to_string(session->state.load())},
            {"depth", session->depth},
            {"mode", session->mode},
            {"cleanup", session->cleanup},
            {"requesterSessionKey", session->requester_session_key},
            {"requesterRunId", session->requester_run_id},
            {"createdAtMs", session->created_at_ms.load()},
            {"startedAtMs", session->started_at_ms.load()},
            {"completedAtMs", session->completed_at_ms.load()},
            {"runtimeMs", compute_runtime_ms_locked(session)},
            {"inputTokens", session->input_tokens.load()},
            {"outputTokens", session->output_tokens.load()},
            {"totalTokens", session->total_tokens.load()},
            {"model", session->model.empty() ? json() : json(session->model)},
            {"thinking", session->thinking.empty() ? json() : json(session->thinking)},
            {"taskPreview", truncate_text(session->task, 320)}
        };
    }

    uint64_t compute_runtime_ms_locked(const std::shared_ptr<session_record_t>& session) const
    {
        const uint64_t started = session->started_at_ms.load();
        if (started == 0)
            return 0;
        const uint64_t finished = session->completed_at_ms.load();
        return (finished == 0 ? now_ms() : finished) - started;
    }

    json build_log_array_locked(const std::shared_ptr<session_record_t>& session, size_t limit) const
    {
        json arr = json::array();
        if (limit == 0)
            return arr;

        const size_t total = session->log_entries.size();
        const size_t start = total > limit ? (total - limit) : 0;
        for (size_t i = start; i < total; ++i)
        {
            const auto& entry = session->log_entries[i];
            arr.push_back({
                {"timestampMs", entry.timestamp_ms},
                {"type", entry.type},
                {"message", entry.message},
                {"data", entry.data}
            });
        }
        return arr;
    }

    std::string build_child_context_locked(
        const std::shared_ptr<session_record_t>& parent,
        const session_record_t& child) const
    {
        std::ostringstream ss;
        ss << "**Sub-agent Assignment:**\n" << child.task << "\n\n";
        ss << "**Requester Session:**\n" << parent->session_key << "\n\n";

        if (!parent->assigned_user_message.empty())
            ss << "**Original User Request:**\n" << truncate_text(parent->assigned_user_message, 12000) << "\n\n";
        if (!parent->assigned_context_block.empty())
            ss << "**Shared Analysis Context:**\n" << truncate_text(parent->assigned_context_block, 32000) << "\n\n";
        if (!parent->assigned_chat_history.empty())
            ss << "**Relevant Conversation History:**\n" << truncate_text(parent->assigned_chat_history, 18000) << "\n\n";

        ss << "**Execution Contract:**\n"
           << "Focus only on the assigned sub-task. Return findings for the requester agent.\n"
           << "Keep the result concrete and tool-backed so it can be announced upstream without extra cleanup.\n";
        return sanitize_utf8(ss.str());
    }

    void append_log_locked(
        const std::shared_ptr<session_record_t>& session,
        const std::string& type,
        const std::string& message,
        const json& data) const
    {
        log_entry_t entry;
        entry.timestamp_ms = now_ms();
        entry.type = sanitize_utf8(type);
        entry.message = sanitize_utf8(message);
        entry.data = data;
        sanitize_json_utf8_inplace(entry.data);
        session->log_entries.push_back(entry);

        std::ofstream out(session->transcript_path, std::ios::app | std::ios::binary);
        if (out.good())
        {
            json row{
                {"timestampMs", entry.timestamp_ms},
                {"type", entry.type},
                {"message", entry.message},
                {"data", entry.data}
            };
            out << json_dump_fast(row) << "\n";
        }
    }

    void queue_announcement_locked(
        const std::shared_ptr<session_record_t>& child,
        const std::string& status,
        const std::string& result_text)
    {
        if (child->requester_session_key.empty() || child->requester_run_id == 0)
            return;

        std::ostringstream ss;
        ss << "### Sub-agent Announcement\n"
           << "Source: subagent\n"
           << "Label: " << child->label << "\n"
           << "SessionKey: " << child->session_key << "\n"
           << "SessionId: " << child->session_id << "\n"
           << "Status: " << status << "\n"
           << "Runtime: " << compute_runtime_ms_locked(child) << "ms\n"
           << "Tokens: in=" << child->input_tokens.load()
           << ", out=" << child->output_tokens.load()
           << ", total=" << child->total_tokens.load() << "\n"
           << "Result:\n" << truncate_text(result_text.empty() ? "(no output)" : result_text, 12000) << "\n"
           << "Rewrite this in normal assistant voice for the user if it is relevant.\n";

        _pending_announcements[child->requester_session_key][child->requester_run_id].push_back(ss.str());
        _update_cv.notify_all();
    }

    void archive_expired_sessions_locked()
    {
        const uint64_t cutoff = now_ms() - static_cast<uint64_t>(_archive_after_minutes) * 60ULL * 1000ULL;
        for (const auto& [_, session] : _sessions_by_key)
        {
            if (session->archived)
                continue;
            const uint64_t completed = session->completed_at_ms.load();
            if (completed == 0 || completed > cutoff)
                continue;
            archive_session_locked(session);
        }
    }

    void archive_session_locked(const std::shared_ptr<session_record_t>& session)
    {
        if (session->archived)
            return;

        session->archived = true;
        session->state = session_state_t::archived;
        if (!session->transcript_path.empty())
        {
            std::filesystem::path original(session->transcript_path);
            std::filesystem::path archived = original;
            archived += ".deleted." + std::to_string(now_ms());
            std::error_code ec;
            if (std::filesystem::exists(original, ec))
                std::filesystem::rename(original, archived, ec);
            if (!ec)
                session->transcript_path = archived.string();
        }

        append_log_locked(session, "archived", "Session archived.", json::object());
    }

    void request_cancel_locked(
        const std::shared_ptr<session_record_t>& session,
        bool cascade,
        size_t* affected)
    {
        const session_state_t old_state = session->state.load();
        if (old_state == session_state_t::completed || old_state == session_state_t::failed
            || old_state == session_state_t::timed_out || old_state == session_state_t::cancelled
            || old_state == session_state_t::archived)
        {
            return;
        }

        session->cancel_requested = true;
        if (old_state == session_state_t::accepted || old_state == session_state_t::queued)
            session->state = session_state_t::cancelled;

        append_log_locked(session, "cancel_requested", "Cancellation requested.", json::object());
        if (affected != nullptr)
            ++(*affected);

        std::function<void()> cb = session->cancel_callback;
        if (cb)
            cb();

        if (cascade)
        {
            for (const auto& child_key : session->child_session_keys)
            {
                auto it = _sessions_by_key.find(child_key);
                if (it != _sessions_by_key.end())
                    request_cancel_locked(it->second, true, affected);
            }
        }

        _update_cv.notify_all();
    }

    static settings_t apply_model_override(settings_t settings, const std::string& model_override)
    {
        const std::string model = trim_copy(model_override);
        if (model.empty())
            return settings;

        qstring provider = ida_utils::qstring_tolower(settings.api_provider.c_str());
        if (provider == "gemini")
            settings.gemini_model_name = model;
        else if (provider == "openai")
            settings.openai_model_name = model;
        else if (provider == "openrouter")
            settings.openrouter_model_name = model;
        else if (provider == "anthropic")
            settings.anthropic_model_name = model;
        else if (provider == "copilot")
            settings.copilot_model_name = model;
        else if (provider == "local_llm" || provider == "local llm")
            settings.local_llm_model_name = model;
        return settings;
    }

    static void apply_thinking_profile(agentic::config_t& config, const std::string& thinking)
    {
        const std::string mode = lower_copy(trim_copy(thinking));
        if (mode.empty() || mode == "inherit")
            return;

        if (mode == "none" || mode == "minimal")
        {
            config.max_rounds = (std::min)(config.max_rounds, 10);
            config.agentic_output_tokens = (std::min)(config.agentic_output_tokens, 4096);
            config.synthesis_output_tokens = (std::min)(config.synthesis_output_tokens, 4096);
        }
        else if (mode == "low")
        {
            config.max_rounds = (std::min)(config.max_rounds, 14);
            config.agentic_output_tokens = (std::min)(config.agentic_output_tokens, 6144);
            config.synthesis_output_tokens = (std::min)(config.synthesis_output_tokens, 6144);
        }
        else if (mode == "medium" || mode == "standard")
        {
            config.max_rounds = (std::min)(config.max_rounds, 20);
            config.agentic_output_tokens = (std::min)(config.agentic_output_tokens, 8192);
            config.synthesis_output_tokens = (std::min)(config.synthesis_output_tokens, 8192);
        }
        else if (mode == "high")
        {
            config.max_rounds = (std::min)(config.max_rounds, 28);
            config.agentic_output_tokens = (std::min)(config.agentic_output_tokens, 12288);
            config.synthesis_output_tokens = (std::min)(config.synthesis_output_tokens, 12288);
        }
    }

    void run_subagent_session(std::shared_ptr<session_record_t> session, settings_t settings_snapshot)
    {
        g_thread_context.session = session;
        g_thread_context.run_id = 0;

        bool lane_acquired = false;
        scope_exit_t lane_guard([this, &lane_acquired]() {
            if (!lane_acquired)
                return;

            std::lock_guard<std::mutex> lock(_mutex);
            if (_active_children > 0)
                --_active_children;
            _update_cv.notify_all();
        });

        {
            std::unique_lock<std::mutex> lock(_mutex);
            session->state = session_state_t::queued;
            append_log_locked(session, "queued", "Waiting for sub-agent concurrency slot.", json::object());
            _update_cv.wait(lock, [&]() {
                return session->cancel_requested.load() || _active_children < _max_concurrent;
            });

            if (!session->cancel_requested.load())
            {
                ++_active_children;
                lane_acquired = true;
            }
        }

        if (session->cancel_requested.load())
        {
            std::lock_guard<std::mutex> lock(_mutex);
            session->completed_at_ms = now_ms();
            session->state = session_state_t::cancelled;
            append_log_locked(session, "cancelled", "Cancelled before execution started.", json::object());
            queue_announcement_locked(session, "cancelled", "Sub-agent was cancelled before it started.");
            return;
        }

        session->started_at_ms = now_ms();
        session->state = session_state_t::running;
        {
            std::lock_guard<std::mutex> lock(_mutex);
            append_log_locked(session, "running", "Sub-agent is now running.", json::object());
        }

        settings_snapshot = apply_model_override(std::move(settings_snapshot), session->model);
        std::unique_ptr<AIClient> client = get_ai_client(settings_snapshot);

        std::atomic<bool> cancelled{false};
        std::atomic<bool> timed_out{false};

        if (!client)
        {
            std::lock_guard<std::mutex> lock(_mutex);
            session->completed_at_ms = now_ms();
            session->state = session_state_t::failed;
            session->error_message = "Failed to initialize AI client for sub-agent.";
            append_log_locked(session, "error", session->error_message, json::object());
            queue_announcement_locked(session, "failed", session->error_message);
            return;
        }

        {
            std::lock_guard<std::mutex> lock(_mutex);
            session->cancel_callback = [&cancelled, raw = client.get()]() {
                cancelled = true;
                if (raw != nullptr)
                    raw->cancel_current_request();
            };
        }

        std::thread watchdog;
        if (session->run_timeout_seconds > 0)
        {
            watchdog = std::thread([session, &cancelled, &timed_out, raw = client.get()]() {
                const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(session->run_timeout_seconds);
                while (std::chrono::steady_clock::now() < deadline)
                {
                    if (cancelled.load())
                        return;
                    const session_state_t state = session->state.load();
                    if (state != session_state_t::queued && state != session_state_t::running && state != session_state_t::accepted)
                        return;
                    std::this_thread::sleep_for(std::chrono::milliseconds(200));
                }
                timed_out = true;
                cancelled = true;
                if (raw != nullptr)
                    raw->cancel_current_request();
            });
        }

        std::string final_text;
        try
        {
            std::string prompt = agentic::build_agentic_prompt(
                session->task,
                session->assigned_context_block,
                session->assigned_chat_history);

            agentic::config_t config;
            config.temperature = settings_snapshot.temperature;
            config.user_message = session->task;
            config.context_block = session->assigned_context_block;
            config.chat_history = session->assigned_chat_history;
            config.max_context_tokens = settings_snapshot.get_active_context_window();
            config.max_rounds = 24;
            config.agentic_output_tokens = 8192;
            config.synthesis_output_tokens = 8192;
            apply_thinking_profile(config, session->thinking);

            session->input_tokens = agentic::estimate_tokens(prompt);

            auto on_progress = [this, session](int round, const std::string& status) {
                std::lock_guard<std::mutex> lock(_mutex);
                append_log_locked(session, "progress",
                    "[" + std::to_string(round) + "] " + sanitize_utf8(status),
                    json{{"round", round}});
            };

            auto on_status = [this, session](const agentic::status_update_t& status) {
                std::lock_guard<std::mutex> lock(_mutex);
                json data{
                    {"round", status.round},
                    {"tool", status.tool_name},
                    {"success", status.tool_success},
                    {"message", status.message},
                    {"reasoning", status.reasoning}
                };
                append_log_locked(session, "status", status.message.empty() ? "status" : status.message, data);
            };

            auto result = agentic::run(client.get(), prompt, config, &cancelled, on_progress, on_status, nullptr);
            final_text = result.final_response;
        }
        catch (const std::exception& e)
        {
            final_text = std::string("Error: Sub-agent exception: ") + e.what();
        }

        cancelled = cancelled.load() || session->cancel_requested.load();
        if (watchdog.joinable())
            watchdog.join();

        {
            std::lock_guard<std::mutex> lock(_mutex);
            session->completed_at_ms = now_ms();
            session->output_tokens = agentic::estimate_tokens(final_text);
            session->total_tokens = session->input_tokens.load() + session->output_tokens.load();
            session->final_result = sanitize_utf8(final_text);

            if (timed_out.load())
            {
                session->state = session_state_t::timed_out;
                session->error_message = "Sub-agent run timed out.";
            }
            else if (session->cancel_requested.load())
            {
                session->state = session_state_t::cancelled;
                session->error_message = "Sub-agent run cancelled.";
            }
            else if (!final_text.empty() && final_text.rfind("Error:", 0) == 0)
            {
                session->state = session_state_t::failed;
                session->error_message = final_text;
            }
            else
            {
                session->state = session_state_t::completed;
            }

            append_log_locked(session, "final",
                session->error_message.empty() ? session->final_result : session->error_message,
                json{{"status", state_to_string(session->state.load())}});

            queue_announcement_locked(session, state_to_string(session->state.load()),
                session->error_message.empty() ? session->final_result : session->error_message);

            session->cancel_callback = nullptr;

            if (session->cleanup == "delete")
                archive_session_locked(session);
        }

        _update_cv.notify_all();
    }

private:
    mutable std::mutex _mutex;
    mutable std::condition_variable _update_cv;
    std::unordered_map<std::string, std::shared_ptr<session_record_t>> _sessions_by_key;
    std::unordered_map<std::string, std::string> _session_key_by_id;
    std::unordered_map<std::string, uint64_t> _next_run_ids;
    std::unordered_map<std::string, std::unordered_map<uint64_t, std::deque<std::string>>> _pending_announcements;
    std::atomic<uint64_t> _session_counter{1};
    int _max_spawn_depth = 2;
    int _max_children_per_agent = 5;
    int _max_concurrent = 4;
    int _default_run_timeout_seconds = 900;
    int _archive_after_minutes = 60;
    int _active_children = 0;
};

class session_scope_t
{
public:
    explicit session_scope_t(std::shared_ptr<session_record_t> session)
        : _previous_session(g_thread_context.session),
          _previous_run_id(g_thread_context.run_id)
    {
        g_thread_context.session = std::move(session);
        g_thread_context.run_id = 0;
    }

    ~session_scope_t()
    {
        g_thread_context.session = _previous_session;
        g_thread_context.run_id = _previous_run_id;
    }

private:
    std::shared_ptr<session_record_t> _previous_session;
    uint64_t _previous_run_id = 0;
};

inline manager_t& manager()
{
    return manager_t::instance();
}

inline bool has_current_session()
{
    return manager().has_current_session();
}

inline bool can_execute_tool(const std::string& tool_name)
{
    return manager().can_execute_tool(tool_name);
}

inline bool is_tool_visible(const std::string& tool_name)
{
    return manager().is_tool_visible(tool_name);
}

inline std::string session_prompt_guidance()
{
    return manager().session_prompt_guidance();
}

inline std::string current_session_key()
{
    return manager().current_session_key();
}

inline uint64_t current_run_id()
{
    return manager().current_run_id();
}

inline int current_depth()
{
    return manager().current_depth();
}

inline int current_active_child_count()
{
    return manager().current_active_child_count();
}

inline uint64_t begin_run_for_current_session(
    const std::string& user_message,
    const std::string& context_block,
    const std::string& chat_history)
{
    return manager().begin_run_for_current_session(user_message, context_block, chat_history);
}

inline void end_run_for_current_session()
{
    manager().end_run_for_current_session();
}

inline std::vector<std::string> take_runtime_updates_for_current_run()
{
    return manager().take_runtime_updates_for_current_run();
}

inline bool wait_for_update_for_current_run(int timeout_ms)
{
    return manager().wait_for_update_for_current_run(timeout_ms);
}

inline json spawn(const spawn_request_t& request)
{
    return manager().spawn(request);
}

inline json list_visible_sessions()
{
    return manager().list_visible_sessions();
}

inline json get_session_info(const std::string& id_or_key, size_t log_limit = 0, bool include_log = false)
{
    return manager().get_session_info(id_or_key, log_limit, include_log);
}

inline json get_session_history(const std::string& id_or_key, size_t limit = 200)
{
    return manager().get_session_history(id_or_key, limit);
}

inline json send_message(const std::string& id_or_key, const std::string& message, bool steer)
{
    return manager().send_message(id_or_key, message, steer);
}

inline json kill(const std::string& id_or_key, bool cascade = true)
{
    return manager().kill(id_or_key, cascade);
}

inline json kill_all_visible(bool cascade = true)
{
    return manager().kill_all_visible(cascade);
}

class run_scope_guard_t
{
public:
    run_scope_guard_t(
        const std::string& user_message,
        const std::string& context_block,
        const std::string& chat_history)
        : _run_was_preexisting(g_thread_context.run_id != 0)
    {
        if (!_run_was_preexisting)
            begin_run_for_current_session(user_message, context_block, chat_history);
    }

    ~run_scope_guard_t()
    {
        if (!_run_was_preexisting)
            end_run_for_current_session();
    }

private:
    bool _run_was_preexisting = false;
};

} // namespace subagents