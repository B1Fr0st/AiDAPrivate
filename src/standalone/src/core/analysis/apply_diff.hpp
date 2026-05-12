#pragma once

#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cmath>


namespace apply_diff {

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


struct hunk_t
{
    int old_start = 0;
    int old_count = 0;
    int new_start = 0;
    int new_count = 0;
    std::vector<std::string> lines;
};


struct diff_result_t
{
    bool success = false;
    std::string content;
    std::string error;
    double similarity = 0.0;
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


namespace detail {

inline double cheap_prefix_similarity(const std::string& a, const std::string& b)
{
    size_t len_a = a.size();
    size_t len_b = b.size();
    size_t max_len = (std::max)(len_a, len_b);
    if (max_len == 0) return 1.0;
    size_t min_len = (std::min)(len_a, len_b);
    size_t matches = 0;
    for (size_t i = 0; i < min_len; ++i) {
        if (a[i] == b[i]) ++matches;
    }
    double ratio = static_cast<double>(matches) / static_cast<double>(max_len);
    if (ratio < 0.0) ratio = 0.0;
    if (ratio > 1.0) ratio = 1.0;
    return ratio;
}

}


inline double cheap_levenshtein_or_prefix_similarity(const std::string& a, const std::string& b)
{
    if (a.empty() && b.empty()) return 1.0;
    if (a.empty() || b.empty()) return 0.0;

    size_t len_a = a.size();
    size_t len_b = b.size();

    if ((std::max)(len_a, len_b) > 500) {
        return detail::cheap_prefix_similarity(a, b);
    }

    std::vector<std::vector<size_t>> dp(len_a + 1, std::vector<size_t>(len_b + 1, 0));

    for (size_t i = 0; i <= len_a; ++i) dp[i][0] = i;
    for (size_t j = 0; j <= len_b; ++j) dp[0][j] = j;

    for (size_t i = 1; i <= len_a; ++i) {
        for (size_t j = 1; j <= len_b; ++j) {
            size_t cost = (a[i - 1] == b[j - 1]) ? 0 : 1;
            dp[i][j] = (std::min)({dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost});
        }
    }

    size_t max_len = (std::max)(len_a, len_b);
    double ratio = 1.0 - static_cast<double>(dp[len_a][len_b]) / static_cast<double>(max_len);
    if (ratio < 0.0) ratio = 0.0;
    if (ratio > 1.0) ratio = 1.0;
    return ratio;
}


inline std::vector<hunk_t> parse_unified_diff(const std::string& diff_text)
{
    std::vector<hunk_t> hunks;
    auto lines = split_lines(diff_text);

    hunk_t current;
    bool in_hunk = false;

    for (const auto& line : lines) {
        if (line.substr(0, 4) == "--- " || line.substr(0, 4) == "+++ ") {
            continue;
        }

        if (line.substr(0, 3) == "@@ ") {
            if (in_hunk) {
                hunks.push_back(current);
            }
            current = hunk_t{};
            in_hunk = true;

            size_t pos1 = line.find('-');
            size_t comma1 = line.find(',', pos1);
            size_t pos2 = line.find('+', pos1);
            size_t comma2 = line.find(',', pos2);
            size_t end = line.find(' ', pos2);

            if (pos1 != std::string::npos && pos2 != std::string::npos) {
                current.old_start = std::atoi(line.c_str() + pos1 + 1);
                current.old_count = (comma1 != std::string::npos && comma1 < pos2)
                    ? std::atoi(line.c_str() + comma1 + 1) : 1;
                current.new_start = std::atoi(line.c_str() + pos2 + 1);
                current.new_count = (comma2 != std::string::npos && (end == std::string::npos || comma2 < end))
                    ? std::atoi(line.c_str() + comma2 + 1) : 1;
            }
            continue;
        }

        if (in_hunk) {
            current.lines.push_back(line);
        }
    }

    if (in_hunk) {
        hunks.push_back(current);
    }

    return hunks;
}


inline int find_best_match_line(
    const std::vector<std::string>& file_lines,
    const std::vector<std::string>& context_lines,
    int hint_line,
    double min_similarity = 0.6)
{
    if (context_lines.empty()) return hint_line;

    int best_line = -1;
    double best_score = 0.0;

    int search_range = 100;
    int start = (std::max)(0, hint_line - search_range);
    int end = (std::min)(static_cast<int>(file_lines.size()) - static_cast<int>(context_lines.size()) + 1,
                          hint_line + search_range);

    for (int i = start; i < end; ++i) {
        double total_sim = 0.0;
        int matched = 0;
        for (size_t j = 0; j < context_lines.size() && (i + static_cast<int>(j)) < static_cast<int>(file_lines.size()); ++j) {
            total_sim += cheap_levenshtein_or_prefix_similarity(file_lines[i + j], context_lines[j]);
            ++matched;
        }
        if (matched > 0) {
            double avg = total_sim / matched;
            int dist = std::abs(i - hint_line);
            double score = avg - dist * 0.0001;
            if (score > best_score) {
                best_score = score;
                best_line = i;
            }
        }
    }

    if (best_score < min_similarity)
        return -1;

    return best_line;
}


inline diff_result_t apply(const std::string& original_content, const std::string& diff_text)
{
    diff_result_t result;

    detail::last_error_ref().clear();

    auto hunks = parse_unified_diff(diff_text);
    if (hunks.empty()) {
        detail::last_error_ref() = "No valid hunks found in diff";
        result.error = detail::last_error_ref();
        return result;
    }

    const std::string eol = text_uses_crlf(original_content) ? "\r\n" : "\n";

    auto file_lines = split_lines(original_content);

    int offset = 0;

    for (const auto& hunk : hunks) {
        std::vector<std::string> context_lines;
        std::vector<std::string> remove_lines;
        std::vector<std::string> add_lines;
        std::vector<std::string> new_block;

        for (const auto& line : hunk.lines) {
            if (line.empty()) {
                context_lines.push_back("");
                new_block.push_back("");
                continue;
            }
            char prefix = line[0];
            std::string content = line.substr(1);
            if (prefix == ' ') {
                context_lines.push_back(content);
                new_block.push_back(content);
            } else if (prefix == '-') {
                context_lines.push_back(content);
                remove_lines.push_back(content);
            } else if (prefix == '+') {
                add_lines.push_back(content);
                new_block.push_back(content);
            }
        }

        int target_line = hunk.old_start - 1 + offset;
        int match_line = find_best_match_line(file_lines, context_lines, target_line);

        if (match_line < 0) {
            detail::last_error_ref() = "Could not find matching context for hunk at line " +
                std::to_string(hunk.old_start);
            result.error = detail::last_error_ref();
            return result;
        }

        int remove_count = static_cast<int>(context_lines.size());

        if (match_line < 0 || static_cast<size_t>(match_line) > file_lines.size() ||
            remove_count < 0 ||
            static_cast<size_t>(match_line) + static_cast<size_t>(remove_count) > file_lines.size()) {
            detail::last_error_ref() = "remove_count exceeds file_lines.size() at hunk near line " +
                std::to_string(hunk.old_start);
            result.error = detail::last_error_ref();
            return result;
        }

        auto it_start = file_lines.begin() + match_line;
        auto it_end = it_start + remove_count;
        file_lines.erase(it_start, it_end);

        for (int i = static_cast<int>(new_block.size()) - 1; i >= 0; --i) {
            file_lines.insert(file_lines.begin() + match_line, new_block[i]);
        }

        offset += static_cast<int>(new_block.size()) - remove_count;
    }

    result.success = true;
    result.content = join_lines(file_lines, eol);
    return result;
}


}
