#pragma once

#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <sstream>


namespace skills {


struct skill_metadata_t
{
    std::string name;
    std::string description;
    std::string source;
    std::vector<std::string> mode_slugs;
    std::string file_path;
};


struct skill_content_t : skill_metadata_t
{
    std::string instructions;
};


inline bool parse_yaml_frontmatter(const std::string& content, skill_metadata_t& meta, std::string& body)
{
    if (content.substr(0, 3) != "---") {
        body = content;
        return false;
    }

    auto end_pos = content.find("\n---", 3);
    if (end_pos == std::string::npos) {
        body = content;
        return false;
    }

    std::string frontmatter = content.substr(3, end_pos - 3);
    body = content.substr(end_pos + 4);
    if (!body.empty() && body[0] == '\n') body = body.substr(1);

    std::istringstream stream(frontmatter);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();

        auto colon_pos = line.find(':');
        if (colon_pos == std::string::npos) continue;

        std::string key = line.substr(0, colon_pos);
        std::string value = line.substr(colon_pos + 1);

        while (!key.empty() && key.front() == ' ') key = key.substr(1);
        while (!key.empty() && key.back() == ' ') key.pop_back();
        while (!value.empty() && value.front() == ' ') value = value.substr(1);
        while (!value.empty() && value.back() == ' ') value.pop_back();

        if (value.front() == '"' && value.back() == '"' && value.size() >= 2)
            value = value.substr(1, value.size() - 2);
        if (value.front() == '\'' && value.back() == '\'' && value.size() >= 2)
            value = value.substr(1, value.size() - 2);

        if (key == "name") {
            meta.name = value;
        } else if (key == "description") {
            meta.description = value;
        } else if (key == "modeSlugs" || key == "mode_slugs") {
            meta.mode_slugs.clear();
            if (value.front() == '[' && value.back() == ']') {
                value = value.substr(1, value.size() - 2);
            }
            std::istringstream vs(value);
            std::string item;
            while (std::getline(vs, item, ',')) {
                while (!item.empty() && item.front() == ' ') item = item.substr(1);
                while (!item.empty() && item.back() == ' ') item.pop_back();
                if (item.front() == '"' && item.back() == '"' && item.size() >= 2)
                    item = item.substr(1, item.size() - 2);
                if (!item.empty())
                    meta.mode_slugs.push_back(item);
            }
        }
    }

    return true;
}


class manager_t
{
public:
    void add_search_path(const std::string& path)
    {
        _search_paths.push_back(path);
    }

    void discover()
    {
        _skills.clear();

        for (const auto& base : _search_paths) {
            if (!std::filesystem::exists(base)) continue;

            for (const auto& entry : std::filesystem::recursive_directory_iterator(base)) {
                if (!entry.is_regular_file()) continue;
                if (entry.path().filename() != "SKILL.md") continue;

                std::ifstream ifs(entry.path());
                if (!ifs) continue;

                std::string content((std::istreambuf_iterator<char>(ifs)),
                                     std::istreambuf_iterator<char>());

                skill_metadata_t meta;
                std::string body;
                parse_yaml_frontmatter(content, meta, body);

                if (meta.name.empty()) {
                    meta.name = entry.path().parent_path().filename().string();
                }
                meta.file_path = entry.path().string();

                if (meta.description.empty())
                    meta.description = "Skill: " + meta.name;

                auto src = entry.path().string();
                if (src.find("AppData") != std::string::npos || src.find("appdata") != std::string::npos)
                    meta.source = "global";
                else
                    meta.source = "project";

                _skills[meta.name] = meta;
            }
        }
    }

    std::vector<skill_metadata_t> get_all() const
    {
        std::vector<skill_metadata_t> result;
        for (const auto& [name, meta] : _skills)
            result.push_back(meta);
        return result;
    }

    std::vector<skill_metadata_t> get_for_mode(const std::string& mode_slug) const
    {
        std::vector<skill_metadata_t> result;
        for (const auto& [name, meta] : _skills) {
            if (meta.mode_slugs.empty()) {
                result.push_back(meta);
            } else {
                for (const auto& slug : meta.mode_slugs) {
                    if (slug == mode_slug) {
                        result.push_back(meta);
                        break;
                    }
                }
            }
        }
        return result;
    }

    skill_content_t resolve(const std::string& name) const
    {
        skill_content_t sc;

        auto it = _skills.find(name);
        if (it == _skills.end()) return sc;

        static_cast<skill_metadata_t&>(sc) = it->second;

        std::ifstream ifs(it->second.file_path);
        if (!ifs) return sc;

        std::string content((std::istreambuf_iterator<char>(ifs)),
                             std::istreambuf_iterator<char>());

        std::string body;
        skill_metadata_t tmp;
        parse_yaml_frontmatter(content, tmp, body);
        sc.instructions = body;

        return sc;
    }

    void reload() { discover(); }

    bool has_skill(const std::string& name) const { return _skills.count(name) > 0; }

private:
    std::vector<std::string> _search_paths;
    std::map<std::string, skill_metadata_t> _skills;
};


}
