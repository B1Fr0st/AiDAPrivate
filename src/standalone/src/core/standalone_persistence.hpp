#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>

#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <algorithm>
#include <cstdint>
#include <mutex>

#include <nlohmann/json.hpp>


namespace task_persistence {


struct task_metadata_t
{
    std::string id;
    std::string title;
    std::string mode_slug        = "agent";
    std::string provider_kind;
    std::string model_name;
    int64_t     created_at       = 0;
    int64_t     updated_at       = 0;
    int         message_count    = 0;
    int64_t     total_input_tokens  = 0;
    int64_t     total_output_tokens = 0;
    double      total_cost_usd   = 0.0;
    std::string status           = "active";
};


struct chat_message_t
{
    std::string text;
    std::string thinking_text;
    bool        is_user         = false;
    bool        has_thinking    = false;
    int64_t     timestamp       = 0;
    int         input_tokens    = 0;
    int         output_tokens   = 0;
    int         cache_read      = 0;
    int         cache_write     = 0;
    bool        is_summary      = false;
    std::string condense_id;
};


struct api_message_t
{
    std::string role;
    nlohmann::json content;
    int64_t     timestamp       = 0;
    bool        is_summary      = false;
    std::string condense_id;
    std::string condense_parent;
};


inline std::filesystem::path get_tasks_dir()
{
    wchar_t* appdata = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
        auto dir = std::filesystem::path(appdata) / L"AiDA" / L"Standalone" / L"tasks";
        CoTaskMemFree(appdata);
        return dir;
    }
    return std::filesystem::current_path() / "aida_tasks";
}


inline std::string generate_task_id()
{
    auto now = std::chrono::system_clock::now().time_since_epoch();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    char buf[64];
    snprintf(buf, sizeof(buf), "task_%lld_%04x",
             static_cast<long long>(ms),
             static_cast<unsigned>(GetTickCount64() & 0xFFFF));
    return buf;
}


inline int64_t unix_timestamp_ms()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}


inline bool save_task(
    const std::string& task_id,
    const task_metadata_t& metadata,
    const std::vector<chat_message_t>& chat_messages,
    const std::vector<api_message_t>& api_messages)
{
    auto task_dir = get_tasks_dir() / task_id;
    std::error_code ec;
    std::filesystem::create_directories(task_dir, ec);
    if (ec) return false;

    using json = nlohmann::json;

    {
        json meta;
        meta["id"]             = metadata.id;
        meta["title"]          = metadata.title;
        meta["mode_slug"]      = metadata.mode_slug;
        meta["provider_kind"]  = metadata.provider_kind;
        meta["model_name"]     = metadata.model_name;
        meta["created_at"]     = metadata.created_at;
        meta["updated_at"]     = metadata.updated_at;
        meta["message_count"]  = metadata.message_count;
        meta["total_input_tokens"]  = metadata.total_input_tokens;
        meta["total_output_tokens"] = metadata.total_output_tokens;
        meta["total_cost_usd"] = metadata.total_cost_usd;
        meta["status"]         = metadata.status;

        std::ofstream ofs(task_dir / "metadata.json", std::ios::binary);
        if (!ofs) return false;
        ofs << meta.dump(2);
    }

    {
        json arr = json::array();
        for (auto& m : chat_messages) {
            json msg;
            msg["text"]          = m.text;
            msg["thinking_text"] = m.thinking_text;
            msg["is_user"]       = m.is_user;
            msg["has_thinking"]  = m.has_thinking;
            msg["timestamp"]     = m.timestamp;
            msg["input_tokens"]  = m.input_tokens;
            msg["output_tokens"] = m.output_tokens;
            msg["cache_read"]    = m.cache_read;
            msg["cache_write"]   = m.cache_write;
            msg["is_summary"]    = m.is_summary;
            msg["condense_id"]   = m.condense_id;
            arr.push_back(std::move(msg));
        }
        std::ofstream ofs(task_dir / "chat_messages.json", std::ios::binary);
        if (!ofs) return false;
        ofs << arr.dump();
    }

    {
        json arr = json::array();
        for (auto& m : api_messages) {
            json msg;
            msg["role"]            = m.role;
            msg["content"]         = m.content;
            msg["timestamp"]       = m.timestamp;
            msg["is_summary"]      = m.is_summary;
            msg["condense_id"]     = m.condense_id;
            msg["condense_parent"] = m.condense_parent;
            arr.push_back(std::move(msg));
        }
        std::ofstream ofs(task_dir / "api_messages.json", std::ios::binary);
        if (!ofs) return false;
        ofs << arr.dump();
    }

    return true;
}


inline bool load_task_metadata(const std::string& task_id, task_metadata_t& out)
{
    auto meta_path = get_tasks_dir() / task_id / "metadata.json";
    std::ifstream ifs(meta_path, std::ios::binary);
    if (!ifs) return false;

    try {
        auto j = nlohmann::json::parse(ifs);
        out.id             = j.value("id", task_id);
        out.title          = j.value("title", "");
        out.mode_slug      = j.value("mode_slug", "agent");
        out.provider_kind  = j.value("provider_kind", "");
        out.model_name     = j.value("model_name", "");
        out.created_at     = j.value("created_at", (int64_t)0);
        out.updated_at     = j.value("updated_at", (int64_t)0);
        out.message_count  = j.value("message_count", 0);
        out.total_input_tokens  = j.value("total_input_tokens", (int64_t)0);
        out.total_output_tokens = j.value("total_output_tokens", (int64_t)0);
        out.total_cost_usd = j.value("total_cost_usd", 0.0);
        out.status         = j.value("status", "active");
        return true;
    } catch (...) {
        return false;
    }
}


inline bool load_chat_messages(const std::string& task_id, std::vector<chat_message_t>& out)
{
    auto path = get_tasks_dir() / task_id / "chat_messages.json";
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;

    try {
        auto arr = nlohmann::json::parse(ifs);
        if (!arr.is_array()) return false;

        out.clear();
        out.reserve(arr.size());
        for (auto& j : arr) {
            chat_message_t m;
            m.text          = j.value("text", "");
            m.thinking_text = j.value("thinking_text", "");
            m.is_user       = j.value("is_user", false);
            m.has_thinking  = j.value("has_thinking", false);
            m.timestamp     = j.value("timestamp", (int64_t)0);
            m.input_tokens  = j.value("input_tokens", 0);
            m.output_tokens = j.value("output_tokens", 0);
            m.cache_read    = j.value("cache_read", 0);
            m.cache_write   = j.value("cache_write", 0);
            m.is_summary    = j.value("is_summary", false);
            m.condense_id   = j.value("condense_id", "");
            out.push_back(std::move(m));
        }
        return true;
    } catch (...) {
        return false;
    }
}


inline bool load_api_messages(const std::string& task_id, std::vector<api_message_t>& out)
{
    auto path = get_tasks_dir() / task_id / "api_messages.json";
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;

    try {
        auto arr = nlohmann::json::parse(ifs);
        if (!arr.is_array()) return false;

        out.clear();
        out.reserve(arr.size());
        for (auto& j : arr) {
            api_message_t m;
            m.role            = j.value("role", "");
            m.content         = j.value("content", nlohmann::json());
            m.timestamp       = j.value("timestamp", (int64_t)0);
            m.is_summary      = j.value("is_summary", false);
            m.condense_id     = j.value("condense_id", "");
            m.condense_parent = j.value("condense_parent", "");
            out.push_back(std::move(m));
        }
        return true;
    } catch (...) {
        return false;
    }
}


inline std::vector<task_metadata_t> list_tasks()
{
    std::vector<task_metadata_t> result;
    auto tasks_dir = get_tasks_dir();

    std::error_code ec;
    if (!std::filesystem::exists(tasks_dir, ec))
        return result;

    for (auto& entry : std::filesystem::directory_iterator(tasks_dir, ec)) {
        if (!entry.is_directory()) continue;
        auto dir_name = entry.path().filename().string();
        task_metadata_t meta;
        if (load_task_metadata(dir_name, meta))
            result.push_back(std::move(meta));
    }

    std::sort(result.begin(), result.end(),
        [](const task_metadata_t& a, const task_metadata_t& b) {
            return a.updated_at > b.updated_at;
        });
    return result;
}


inline bool delete_task(const std::string& task_id)
{
    if (task_id.empty()) return false;

    auto task_dir = get_tasks_dir() / task_id;
    std::error_code ec;
    if (!std::filesystem::exists(task_dir, ec))
        return false;

    return std::filesystem::remove_all(task_dir, ec) > 0;
}


inline std::string extract_title_from_first_message(const std::string& text, int max_len = 60)
{
    if (text.empty()) return "New Chat";
    std::string title = text.substr(0, static_cast<size_t>(max_len));

    auto nl = title.find('\n');
    if (nl != std::string::npos) title = title.substr(0, nl);

    while (!title.empty() && (title.back() == ' ' || title.back() == '\n' || title.back() == '\r'))
        title.pop_back();

    if (title.size() >= static_cast<size_t>(max_len) - 3)
        title += "...";

    return title.empty() ? "New Chat" : title;
}

}
