#pragma once

#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <fstream>
#include <cstdint>
#include <chrono>
#include <sstream>
#include <algorithm>

#include <nlohmann/json.hpp>


namespace checkpoints {


struct file_snapshot_t
{
    std::string relative_path;
    std::string content_hash;
    int64_t     size = 0;
};


struct checkpoint_t
{
    std::string id;
    std::string task_id;
    std::string message;
    int64_t     timestamp = 0;
    int         message_index = -1;
    std::vector<file_snapshot_t> files;
};


inline std::string make_checkpoint_id()
{
    auto now = std::chrono::system_clock::now().time_since_epoch();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    char buf[32];
    snprintf(buf, sizeof(buf), "cp_%lld", ms);
    return buf;
}


inline std::string hash_content(const std::string& content)
{
    uint64_t h = 14695981039346656037ULL;
    for (unsigned char c : content) {
        h ^= c;
        h *= 1099511628211ULL;
    }
    char buf[20];
    snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(h));
    return buf;
}


class service_t
{
public:
    explicit service_t(const std::string& workspace_root) : _workspace(workspace_root) {}

    void set_storage_dir(const std::string& dir) { _storage = dir; }

    bool save_checkpoint(
        const std::string& task_id,
        const std::string& message,
        int message_index,
        const std::vector<std::string>& tracked_files)
    {
        checkpoint_t cp;
        cp.id = make_checkpoint_id();
        cp.task_id = task_id;
        cp.message = message;
        cp.message_index = message_index;
        cp.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        auto cp_dir = checkpoint_dir(task_id, cp.id);
        std::error_code ec;
        std::filesystem::create_directories(cp_dir, ec);
        if (ec) return false;

        for (const auto& rel_path : tracked_files) {
            auto full_path = std::filesystem::path(_workspace) / rel_path;
            if (!std::filesystem::exists(full_path)) continue;

            std::ifstream ifs(full_path, std::ios::binary);
            if (!ifs) continue;

            std::string content((std::istreambuf_iterator<char>(ifs)),
                                 std::istreambuf_iterator<char>());

            file_snapshot_t snap;
            snap.relative_path = rel_path;
            snap.content_hash = hash_content(content);
            snap.size = static_cast<int64_t>(content.size());
            cp.files.push_back(snap);

            auto dest = std::filesystem::path(cp_dir) / rel_path;
            std::filesystem::create_directories(dest.parent_path(), ec);
            std::ofstream ofs(dest, std::ios::binary);
            if (ofs) ofs.write(content.data(), content.size());
        }

        save_manifest(task_id, cp);

        auto& task_cps = _checkpoints[task_id];
        task_cps.push_back(cp);
        return true;
    }

    bool restore_checkpoint(const std::string& task_id, const std::string& checkpoint_id)
    {
        auto cp_dir = checkpoint_dir(task_id, checkpoint_id);
        if (!std::filesystem::exists(cp_dir)) return false;

        auto manifest = load_manifest(task_id, checkpoint_id);
        if (manifest.id.empty()) return false;

        for (const auto& snap : manifest.files) {
            auto src = std::filesystem::path(cp_dir) / snap.relative_path;
            auto dest = std::filesystem::path(_workspace) / snap.relative_path;

            if (!std::filesystem::exists(src)) continue;

            std::error_code ec;
            std::filesystem::create_directories(dest.parent_path(), ec);

            std::ifstream ifs(src, std::ios::binary);
            if (!ifs) continue;

            std::string content((std::istreambuf_iterator<char>(ifs)),
                                 std::istreambuf_iterator<char>());

            std::ofstream ofs(dest, std::ios::binary | std::ios::trunc);
            if (ofs) ofs.write(content.data(), content.size());
        }

        return true;
    }

    std::vector<checkpoint_t> list_checkpoints(const std::string& task_id) const
    {
        auto it = _checkpoints.find(task_id);
        if (it != _checkpoints.end()) return it->second;

        std::vector<checkpoint_t> result;
        auto task_dir = std::filesystem::path(_storage) / task_id;
        if (!std::filesystem::exists(task_dir)) return result;

        for (const auto& entry : std::filesystem::directory_iterator(task_dir)) {
            if (!entry.is_directory()) continue;
            auto cp = load_manifest(task_id, entry.path().filename().string());
            if (!cp.id.empty())
                result.push_back(cp);
        }

        std::sort(result.begin(), result.end(),
                  [](const checkpoint_t& a, const checkpoint_t& b) { return a.timestamp < b.timestamp; });
        return result;
    }

    std::vector<std::pair<std::string, std::string>> get_diff(
        const std::string& task_id,
        const std::string& cp_a,
        const std::string& cp_b) const
    {
        std::vector<std::pair<std::string, std::string>> changes;

        auto dir_a = checkpoint_dir(task_id, cp_a);
        auto dir_b = checkpoint_dir(task_id, cp_b);

        auto manifest_b = load_manifest(task_id, cp_b);
        for (const auto& snap : manifest_b.files) {
            auto file_a = std::filesystem::path(dir_a) / snap.relative_path;
            auto file_b = std::filesystem::path(dir_b) / snap.relative_path;

            std::string content_a, content_b;
            if (std::filesystem::exists(file_a)) {
                std::ifstream ifs(file_a, std::ios::binary);
                content_a.assign((std::istreambuf_iterator<char>(ifs)),
                                  std::istreambuf_iterator<char>());
            }
            if (std::filesystem::exists(file_b)) {
                std::ifstream ifs(file_b, std::ios::binary);
                content_b.assign((std::istreambuf_iterator<char>(ifs)),
                                  std::istreambuf_iterator<char>());
            }

            if (content_a != content_b) {
                changes.emplace_back(snap.relative_path,
                    content_a.empty() ? "[new file]" : "[modified]");
            }
        }

        return changes;
    }

private:
    std::string _workspace;
    std::string _storage;
    std::map<std::string, std::vector<checkpoint_t>> _checkpoints;

    std::string checkpoint_dir(const std::string& task_id, const std::string& cp_id) const
    {
        return (std::filesystem::path(_storage) / task_id / cp_id).string();
    }

    void save_manifest(const std::string& task_id, const checkpoint_t& cp) const
    {
        nlohmann::json j;
        j["id"] = cp.id;
        j["task_id"] = cp.task_id;
        j["message"] = cp.message;
        j["timestamp"] = cp.timestamp;
        j["message_index"] = cp.message_index;

        auto files = nlohmann::json::array();
        for (const auto& f : cp.files) {
            files.push_back({{"path", f.relative_path}, {"hash", f.content_hash}, {"size", f.size}});
        }
        j["files"] = files;

        auto path = std::filesystem::path(checkpoint_dir(task_id, cp.id)) / "manifest.json";
        std::error_code ec;
        std::filesystem::create_directories(path.parent_path(), ec);
        std::ofstream ofs(path);
        if (ofs) ofs << j.dump(2);
    }

    checkpoint_t load_manifest(const std::string& task_id, const std::string& cp_id) const
    {
        checkpoint_t cp;
        auto path = std::filesystem::path(checkpoint_dir(task_id, cp_id)) / "manifest.json";
        if (!std::filesystem::exists(path)) return cp;

        std::ifstream ifs(path);
        if (!ifs) return cp;

        auto j = nlohmann::json::parse(ifs, nullptr, false);
        if (j.is_discarded()) return cp;

        cp.id = j.value("id", "");
        cp.task_id = j.value("task_id", "");
        cp.message = j.value("message", "");
        cp.timestamp = j.value("timestamp", (int64_t)0);
        cp.message_index = j.value("message_index", -1);

        if (j.contains("files") && j["files"].is_array()) {
            for (const auto& f : j["files"]) {
                file_snapshot_t snap;
                snap.relative_path = f.value("path", "");
                snap.content_hash = f.value("hash", "");
                snap.size = f.value("size", (int64_t)0);
                cp.files.push_back(snap);
            }
        }

        return cp;
    }
};


}
