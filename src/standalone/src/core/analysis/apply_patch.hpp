#pragma once

#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <map>
#include <filesystem>
#include <functional>


namespace apply_patch {

namespace detail {
inline std::string& last_error_ref()
{
    static std::string s_last_error;
    return s_last_error;
}
}

inline const std::string& last_error()
{
    return detail::last_error_ref();
}


enum class file_action_t
{
    add_file,
    delete_file,
    update_file,
    move_file
};


struct file_hunk_t
{
    std::vector<std::string> context_before;
    std::vector<std::string> removals;
    std::vector<std::string> additions;
};


struct file_patch_t
{
    file_action_t action     = file_action_t::update_file;
    std::string   path;
    std::string   move_to;
    std::vector<file_hunk_t> hunks;
};


struct patch_result_t
{
    bool success = false;
    std::string error;
    std::map<std::string, std::string> modified_files;
    std::vector<std::string> deleted_files;
    std::map<std::string, std::string> moved_files;
};


inline std::vector<std::string> split_lines(const std::string& text)
{
    std::vector<std::string> lines;
    std::istringstream stream(text);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        lines.push_back(line);
    }
    return lines;
}


inline bool text_uses_crlf(const std::string& text)
{
    size_t crlf = 0;
    size_t lf_only = 0;
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\n') {
            if (i > 0 && text[i - 1] == '\r') ++crlf;
            else ++lf_only;
        }
    }
    if (crlf == 0 && lf_only == 0) return false;
    return crlf >= lf_only;
}


inline std::string join_lines(const std::vector<std::string>& lines, const std::string& eol = "\n")
{
    std::string result;
    for (size_t i = 0; i < lines.size(); ++i) {
        if (i > 0) result += eol;
        result += lines[i];
    }
    return result;
}


inline std::vector<file_patch_t> parse(const std::string& patch_text)
{
    std::vector<file_patch_t> patches;
    auto lines = split_lines(patch_text);

    bool in_patch = false;
    file_patch_t current;
    file_hunk_t current_hunk;
    bool in_hunk = false;

    for (size_t i = 0; i < lines.size(); ++i) {
        const auto& line = lines[i];

        if (line == "*** Begin Patch") {
            in_patch = true;
            continue;
        }
        if (line == "*** End Patch") {
            if (in_hunk && (!current_hunk.context_before.empty() || !current_hunk.removals.empty() || !current_hunk.additions.empty())) {
                current.hunks.push_back(current_hunk);
            }
            if (!current.path.empty()) {
                patches.push_back(current);
            }
            break;
        }

        if (!in_patch) continue;

        if (line.substr(0, 14) == "*** Add File: ") {
            if (in_hunk && (!current_hunk.context_before.empty() || !current_hunk.removals.empty() || !current_hunk.additions.empty())) {
                current.hunks.push_back(current_hunk);
            }
            if (!current.path.empty()) {
                patches.push_back(current);
            }
            current = file_patch_t{};
            current_hunk = file_hunk_t{};
            in_hunk = true;
            current.action = file_action_t::add_file;
            current.path = line.substr(14);
            continue;
        }

        if (line.substr(0, 17) == "*** Delete File: ") {
            if (in_hunk && (!current_hunk.context_before.empty() || !current_hunk.removals.empty() || !current_hunk.additions.empty())) {
                current.hunks.push_back(current_hunk);
            }
            if (!current.path.empty()) {
                patches.push_back(current);
            }
            current = file_patch_t{};
            current_hunk = file_hunk_t{};
            in_hunk = false;
            current.action = file_action_t::delete_file;
            current.path = line.substr(17);
            continue;
        }

        if (line.substr(0, 17) == "*** Update File: ") {
            if (in_hunk && (!current_hunk.context_before.empty() || !current_hunk.removals.empty() || !current_hunk.additions.empty())) {
                current.hunks.push_back(current_hunk);
            }
            if (!current.path.empty()) {
                patches.push_back(current);
            }
            current = file_patch_t{};
            current_hunk = file_hunk_t{};
            in_hunk = true;
            current.action = file_action_t::update_file;
            current.path = line.substr(17);
            continue;
        }

        if (line.substr(0, 13) == "*** Move to: ") {
            current.action = file_action_t::move_file;
            current.move_to = line.substr(13);
            continue;
        }

        if (line == "***") {
            if (in_hunk && (!current_hunk.context_before.empty() || !current_hunk.removals.empty() || !current_hunk.additions.empty())) {
                current.hunks.push_back(current_hunk);
                current_hunk = file_hunk_t{};
            }
            continue;
        }

        if (!in_hunk) continue;

        if (line.empty()) {
            current_hunk.context_before.push_back("");
            continue;
        }

        char prefix = line[0];
        std::string content = line.substr(1);

        if (prefix == ' ') {
            current_hunk.context_before.push_back(content);
        } else if (prefix == '-') {
            current_hunk.removals.push_back(content);
        } else if (prefix == '+') {
            current_hunk.additions.push_back(content);
        }
    }

    return patches;
}


inline int find_context_match(
    const std::vector<std::string>& file_lines,
    const std::vector<std::string>& context,
    int start_from = 0)
{
    if (context.empty()) return start_from;

    for (int i = start_from; i <= static_cast<int>(file_lines.size()) - static_cast<int>(context.size()); ++i) {
        bool match = true;
        for (size_t j = 0; j < context.size(); ++j) {
            if (file_lines[i + j] != context[j]) {
                match = false;
                break;
            }
        }
        if (match) return i;
    }
    return -1;
}


inline patch_result_t apply(
    const std::string& patch_text,
    std::function<std::string(const std::string&)> read_file,
    std::function<bool(const std::string&, const std::string&)> write_file,
    std::function<bool(const std::string&)> delete_file_fn,
    std::function<bool(const std::string&, const std::string&)> move_file_fn)
{
    patch_result_t result;

    detail::last_error_ref().clear();

    auto patches = parse(patch_text);
    if (patches.empty()) {
        detail::last_error_ref() = "No valid file patches found";
        result.error = detail::last_error_ref();
        return result;
    }

    for (const auto& patch : patches) {
        switch (patch.action) {
        case file_action_t::add_file: {
            std::vector<std::string> new_lines;
            for (const auto& hunk : patch.hunks) {
                for (const auto& line : hunk.additions)
                    new_lines.push_back(line);
            }
            std::string content = join_lines(new_lines);
            if (!write_file(patch.path, content)) {
                detail::last_error_ref() = "Failed to write new file: " + patch.path;
                result.error = detail::last_error_ref();
                return result;
            }
            result.modified_files[patch.path] = content;
            break;
        }

        case file_action_t::delete_file: {
            if (!delete_file_fn) {
                detail::last_error_ref() = "delete_file callback is null but a delete action was encountered for: " + patch.path;
                result.error = detail::last_error_ref();
                return result;
            }
            if (!delete_file_fn(patch.path)) {
                detail::last_error_ref() = "Failed to delete file: " + patch.path;
                result.error = detail::last_error_ref();
                return result;
            }
            result.deleted_files.push_back(patch.path);
            break;
        }

        case file_action_t::move_file: {
            std::string content = read_file(patch.path);
            const std::string eol = text_uses_crlf(content) ? "\r\n" : "\n";
            auto file_lines = split_lines(content);

            for (auto it = patch.hunks.rbegin(); it != patch.hunks.rend(); ++it) {
                int pos = find_context_match(file_lines, it->context_before);
                if (pos < 0) {
                    detail::last_error_ref() = "Context not found in " + patch.path;
                    result.error = detail::last_error_ref();
                    return result;
                }

                int ctx_end = pos + static_cast<int>(it->context_before.size());
                int remove_start = ctx_end;
                int remove_end = remove_start + static_cast<int>(it->removals.size());
                if (remove_end > static_cast<int>(file_lines.size()))
                    remove_end = static_cast<int>(file_lines.size());

                file_lines.erase(file_lines.begin() + remove_start, file_lines.begin() + remove_end);
                for (int j = static_cast<int>(it->additions.size()) - 1; j >= 0; --j)
                    file_lines.insert(file_lines.begin() + remove_start, it->additions[j]);
            }

            std::string new_content = join_lines(file_lines, eol);
            if (!move_file_fn) {
                detail::last_error_ref() = "move_file callback is null but a move action was encountered for: " + patch.path;
                result.error = detail::last_error_ref();
                return result;
            }
            if (!move_file_fn(patch.path, patch.move_to)) {
                detail::last_error_ref() = "Failed to move file: " + patch.path + " -> " + patch.move_to;
                result.error = detail::last_error_ref();
                return result;
            }
            if (!write_file(patch.move_to, new_content)) {
                detail::last_error_ref() = "Failed to write moved file: " + patch.move_to;
                result.error = detail::last_error_ref();
                return result;
            }
            result.moved_files[patch.path] = patch.move_to;
            result.modified_files[patch.move_to] = new_content;
            break;
        }

        case file_action_t::update_file: {
            std::string content = read_file(patch.path);
            const std::string eol = text_uses_crlf(content) ? "\r\n" : "\n";
            auto file_lines = split_lines(content);

            for (auto it = patch.hunks.rbegin(); it != patch.hunks.rend(); ++it) {
                int pos = find_context_match(file_lines, it->context_before);
                if (pos < 0) {
                    detail::last_error_ref() = "Context not found in " + patch.path + " for hunk";
                    result.error = detail::last_error_ref();
                    return result;
                }

                int ctx_end = pos + static_cast<int>(it->context_before.size());
                int remove_start = ctx_end;
                int remove_end = remove_start + static_cast<int>(it->removals.size());
                if (remove_end > static_cast<int>(file_lines.size()))
                    remove_end = static_cast<int>(file_lines.size());

                file_lines.erase(file_lines.begin() + remove_start, file_lines.begin() + remove_end);
                for (int j = static_cast<int>(it->additions.size()) - 1; j >= 0; --j)
                    file_lines.insert(file_lines.begin() + remove_start, it->additions[j]);
            }

            std::string new_content = join_lines(file_lines, eol);
            if (!write_file(patch.path, new_content)) {
                detail::last_error_ref() = "Failed to write updated file: " + patch.path;
                result.error = detail::last_error_ref();
                return result;
            }
            result.modified_files[patch.path] = new_content;
            break;
        }
        }
    }

    result.success = true;
    return result;
}


}
