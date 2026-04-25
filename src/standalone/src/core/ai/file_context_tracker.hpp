#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <regex>


namespace file_context {


enum class record_state_t
{
    active,
    stale
};

enum class record_source_t
{
    read_tool,
    ai_edited,
    user_edited,
    file_mentioned
};


struct entry_t
{
    std::string      path;
    record_state_t   state   = record_state_t::active;
    record_source_t  source  = record_source_t::read_tool;
    int64_t          read_ts = 0;
    int64_t          edit_ts = 0;
    int64_t          user_edit_ts = 0;
    int64_t          token_estimate = 0;
};


inline int64_t now_ms()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}


class tracker_t
{
public:
    void record_read(const std::string& path)
    {
        std::lock_guard<std::mutex> lk(_mtx);
        auto& e = get_or_create(path);
        e.state = record_state_t::active;
        e.source = record_source_t::read_tool;
        e.read_ts = now_ms();
    }

    void record_ai_edit(const std::string& path)
    {
        std::lock_guard<std::mutex> lk(_mtx);
        auto& e = get_or_create(path);
        e.state = record_state_t::active;
        e.source = record_source_t::ai_edited;
        e.edit_ts = now_ms();
        _recently_edited_by_ai.push_back(path);
    }

    void record_user_edit(const std::string& path)
    {
        std::lock_guard<std::mutex> lk(_mtx);
        auto it = _entries.find(normalize(path));
        if (it == _entries.end()) return;

        auto norm = normalize(path);
        bool was_ai_edit = false;
        for (auto rit = _recently_edited_by_ai.rbegin(); rit != _recently_edited_by_ai.rend(); ++rit) {
            if (normalize(*rit) == norm) {
                was_ai_edit = true;
                _recently_edited_by_ai.erase(std::next(rit).base());
                break;
            }
        }

        if (!was_ai_edit) {
            it->second.state = record_state_t::stale;
            it->second.source = record_source_t::user_edited;
            it->second.user_edit_ts = now_ms();
        }
    }

    void record_mention(const std::string& path)
    {
        std::lock_guard<std::mutex> lk(_mtx);
        auto& e = get_or_create(path);
        if (e.source != record_source_t::read_tool && e.source != record_source_t::ai_edited)
            e.source = record_source_t::file_mentioned;
    }

    void update_token_estimate(const std::string& path, int64_t tokens)
    {
        std::lock_guard<std::mutex> lk(_mtx);
        auto it = _entries.find(normalize(path));
        if (it != _entries.end())
            it->second.token_estimate = tokens;
    }

    void mark_stale(const std::string& path)
    {
        std::lock_guard<std::mutex> lk(_mtx);
        auto it = _entries.find(normalize(path));
        if (it != _entries.end())
            it->second.state = record_state_t::stale;
    }

    std::vector<entry_t> get_active_files() const
    {
        std::lock_guard<std::mutex> lk(_mtx);
        std::vector<entry_t> result;
        for (auto& [k, v] : _entries) {
            if (v.state == record_state_t::active)
                result.push_back(v);
        }
        std::sort(result.begin(), result.end(),
            [](const entry_t& a, const entry_t& b) {
                int64_t ts_a = (std::max)(a.read_ts, a.edit_ts);
                int64_t ts_b = (std::max)(b.read_ts, b.edit_ts);
                return ts_a > ts_b;
            });
        return result;
    }

    std::vector<entry_t> get_all_files() const
    {
        std::lock_guard<std::mutex> lk(_mtx);
        std::vector<entry_t> result;
        for (auto& [k, v] : _entries)
            result.push_back(v);
        return result;
    }

    int64_t total_active_tokens() const
    {
        std::lock_guard<std::mutex> lk(_mtx);
        int64_t total = 0;
        for (auto& [k, v] : _entries) {
            if (v.state == record_state_t::active)
                total += v.token_estimate;
        }
        return total;
    }

    void clear()
    {
        std::lock_guard<std::mutex> lk(_mtx);
        _entries.clear();
        _recently_edited_by_ai.clear();
    }

    size_t size() const
    {
        std::lock_guard<std::mutex> lk(_mtx);
        return _entries.size();
    }

private:
    mutable std::mutex _mtx;
    std::map<std::string, entry_t> _entries;
    std::vector<std::string> _recently_edited_by_ai;

    static std::string normalize(const std::string& path)
    {
        std::string result = path;
        std::replace(result.begin(), result.end(), '\\', '/');
        std::transform(result.begin(), result.end(), result.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return result;
    }

    entry_t& get_or_create(const std::string& path)
    {
        auto key = normalize(path);
        auto it = _entries.find(key);
        if (it != _entries.end()) return it->second;

        entry_t e;
        e.path = path;
        auto res = _entries.emplace(key, e);
        return res.first->second;
    }
};


struct mention_t
{
    enum class type_t { file, problems, terminal, git_changes };
    type_t      kind;
    std::string value;
};


inline std::vector<mention_t> parse_mentions(const std::string& text)
{
    std::vector<mention_t> mentions;

    static const std::regex re(
        R"((?:^|\s)@((?:[/\\]|[a-zA-Z]:[/\\])[^\s]+|problems\b|git-changes\b|terminal\b))",
        std::regex_constants::ECMAScript);

    auto begin = std::sregex_iterator(text.begin(), text.end(), re);
    auto end   = std::sregex_iterator();

    for (auto it = begin; it != end; ++it) {
        std::string match = (*it)[1].str();

        if (match == "problems") {
            mentions.push_back({mention_t::type_t::problems, match});
        } else if (match == "terminal") {
            mentions.push_back({mention_t::type_t::terminal, match});
        } else if (match == "git-changes") {
            mentions.push_back({mention_t::type_t::git_changes, match});
        } else {
            std::string cleaned = match;
            while (!cleaned.empty() && (cleaned.back() == '.' || cleaned.back() == ',' ||
                                         cleaned.back() == ';' || cleaned.back() == ':'))
                cleaned.pop_back();
            if (!cleaned.empty())
                mentions.push_back({mention_t::type_t::file, cleaned});
        }
    }
    return mentions;
}


inline std::string resolve_mention_content(
    const mention_t& mention,
    const std::string& workspace_root)
{
    switch (mention.kind) {
    case mention_t::type_t::file:
    {
        std::string path = mention.value;
        std::replace(path.begin(), path.end(), '/', '\\');

        if (path.size() < 2 || path[1] != ':') {
            if (!workspace_root.empty()) {
                std::string ws = workspace_root;
                if (ws.back() != '\\' && ws.back() != '/')
                    ws += '\\';
                path = ws + path;
            }
        }

        std::ifstream ifs(path, std::ios::binary);
        if (!ifs) return "[File not found: " + mention.value + "]";

        std::string content((std::istreambuf_iterator<char>(ifs)),
                             std::istreambuf_iterator<char>());

        constexpr size_t MAX_FILE_SIZE = 100 * 1024;
        if (content.size() > MAX_FILE_SIZE)
            content = content.substr(0, MAX_FILE_SIZE) + "\n[... truncated]";

        return "File: " + mention.value + "\n```\n" + content + "\n```";
    }

    case mention_t::type_t::problems:
        return "[Build problems: not yet integrated]";

    case mention_t::type_t::terminal:
        return "[Terminal output: use terminal_view to capture]";

    case mention_t::type_t::git_changes:
    {
        std::string cwd = workspace_root.empty() ? "." : workspace_root;
        return "[Git changes: run 'git diff' in workspace]";
    }
    }
    return "";
}


inline std::string build_environment_details(
    const std::string& workspace_root,
    const std::string& active_mode,
    bool process_attached,
    const std::string& attached_process_name,
    unsigned long attached_pid,
    const std::vector<std::string>& available_tool_groups)
{
    std::string env;
    env.reserve(2048);

    env += "# Environment Details\n\n";

    env += "- **OS:** Windows (x64)\n";
    env += "- **Shell:** PowerShell\n";

    if (!workspace_root.empty())
        env += "- **Workspace:** " + workspace_root + "\n";

    env += "- **Mode:** " + active_mode + "\n";

    if (process_attached) {
        env += "- **Attached Process:** " + attached_process_name +
               " (PID " + std::to_string(attached_pid) + ")\n";
    }

    if (!available_tool_groups.empty()) {
        env += "- **Available Tool Groups:** ";
        for (size_t i = 0; i < available_tool_groups.size(); ++i) {
            if (i > 0) env += ", ";
            env += available_tool_groups[i];
        }
        env += "\n";
    }

    return env;
}


}
