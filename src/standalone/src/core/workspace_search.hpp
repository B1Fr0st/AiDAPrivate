#pragma once


#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include "work_queue.hpp"

#include <atomic>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <regex>
#include <string>
#include <thread>
#include <vector>

namespace workspace_search
{


struct MatchResult
{
    std::string filepath;
    std::string filename;
    int         line_number;
    int         col_start;
    int         col_end;
    std::string line_text;
};


struct SearchState
{

    char            query_buf[512]  = {};
    char            include_buf[256] = {};
    char            exclude_buf[256] = {};
    bool            case_sensitive   = false;
    bool            whole_word       = false;
    bool            use_regex        = false;


    std::mutex                    results_mtx;
    std::vector<MatchResult>      results;
    int                           selected_idx = -1;


    std::atomic<bool>             searching{false};
    std::atomic<bool>             cancel{false};
    std::atomic<int>              files_scanned{0};
    std::atomic<int>              match_count{0};


    bool                          panel_open = false;
};

inline SearchState g_search;


inline bool is_text_extension(const std::string& ext)
{
    static const char* exts[] = {
        ".c", ".cpp", ".cxx", ".cc", ".h", ".hpp", ".hxx", ".inl",
        ".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".xml", ".yaml", ".yml",
        ".toml", ".ini", ".cfg", ".conf", ".txt", ".md", ".rst",
        ".asm", ".s", ".def", ".rc", ".cmake", ".bat", ".ps1", ".sh",
        ".html", ".htm", ".css", ".scss", ".less", ".sql", ".graphql",
        ".rs", ".go", ".java", ".kt", ".cs", ".fs", ".lua", ".rb",
        ".php", ".swift", ".m", ".mm", ".gradle", ".properties",
        ".log", ".csv", ".tsv", ".env", ".gitignore", ".editorconfig",
        nullptr
    };
    std::string lower = ext;
    for (auto& ch : lower) ch = static_cast<char>(tolower(static_cast<unsigned char>(ch)));
    for (int i = 0; exts[i]; ++i)
        if (lower == exts[i]) return true;
    return false;
}


inline bool glob_match(const std::string& pattern, const std::string& text)
{
    size_t pi = 0, ti = 0;
    size_t star_p = std::string::npos, star_t = 0;
    while (ti < text.size()) {
        if (pi < pattern.size() && (pattern[pi] == '?' ||
            tolower(static_cast<unsigned char>(pattern[pi])) ==
            tolower(static_cast<unsigned char>(text[ti])))) {
            ++pi; ++ti;
        } else if (pi < pattern.size() && pattern[pi] == '*') {
            star_p = pi++;
            star_t = ti;
        } else if (star_p != std::string::npos) {
            pi = star_p + 1;
            ti = ++star_t;
        } else {
            return false;
        }
    }
    while (pi < pattern.size() && pattern[pi] == '*') ++pi;
    return pi == pattern.size();
}


inline std::vector<std::string> parse_globs(const char* buf)
{
    std::vector<std::string> out;
    std::string s(buf);
    size_t pos = 0;
    while (pos < s.size()) {
        size_t comma = s.find(',', pos);
        if (comma == std::string::npos) comma = s.size();
        std::string pat = s.substr(pos, comma - pos);

        while (!pat.empty() && pat.front() == ' ') pat.erase(pat.begin());
        while (!pat.empty() && pat.back() == ' ')  pat.pop_back();
        if (!pat.empty()) out.push_back(std::move(pat));
        pos = comma + 1;
    }
    return out;
}


inline void search_worker(std::string root_dir, std::string query,
                          bool case_sensitive, bool whole_word, bool use_regex,
                          std::vector<std::string> include_globs,
                          std::vector<std::string> exclude_globs)
{
    auto& st = g_search;
    st.files_scanned.store(0);
    st.match_count.store(0);
    {
        std::lock_guard<std::mutex> lk(st.results_mtx);
        st.results.clear();
        st.selected_idx = -1;
    }


    std::regex re;
    if (use_regex) {
        try {
            auto flags = std::regex_constants::ECMAScript;
            if (!case_sensitive) flags |= std::regex_constants::icase;
            re = std::regex(query, flags);
        } catch (...) {
            st.searching.store(false);
            return;
        }
    }


    std::string query_lower = query;
    if (!case_sensitive)
        for (auto& ch : query_lower)
            ch = static_cast<char>(tolower(static_cast<unsigned char>(ch)));

    std::error_code ec;
    for (auto it = std::filesystem::recursive_directory_iterator(root_dir, ec);
         it != std::filesystem::recursive_directory_iterator(); ++it)
    {
        if (st.cancel.load(std::memory_order_acquire))
            break;

        if (!it->is_regular_file(ec))
            continue;

        const auto& path = it->path();
        const std::string ext = path.extension().string();
        const std::string fname = path.filename().string();


        if (!is_text_extension(ext) && !ext.empty())
            continue;


        if (!include_globs.empty()) {
            bool match = false;
            for (const auto& g : include_globs)
                if (glob_match(g, fname)) { match = true; break; }
            if (!match) continue;
        }


        {
            bool skip = false;
            for (const auto& g : exclude_globs)
                if (glob_match(g, fname)) { skip = true; break; }
            if (skip) continue;
        }


        {
            const std::string ps = path.string();
            if (ps.find("\\.git\\") != std::string::npos ||
                ps.find("\\node_modules\\") != std::string::npos ||
                ps.find("\\__pycache__\\") != std::string::npos ||
                ps.find("\\.vs\\") != std::string::npos ||
                ps.find("\\Release\\") != std::string::npos ||
                ps.find("\\Debug\\") != std::string::npos)
                continue;
        }


        std::ifstream ifs(path, std::ios::in);
        if (!ifs.is_open()) continue;

        st.files_scanned.fetch_add(1, std::memory_order_relaxed);

        std::string line;
        int line_no = 0;
        while (std::getline(ifs, line)) {
            ++line_no;
            if (st.cancel.load(std::memory_order_acquire))
                break;

            if (use_regex) {
                std::smatch sm;
                if (std::regex_search(line, sm, re)) {
                    MatchResult mr;
                    mr.filepath = path.string();
                    mr.filename = fname;
                    mr.line_number = line_no;
                    mr.col_start = static_cast<int>(sm.position(0));
                    mr.col_end = mr.col_start + static_cast<int>(sm.length(0));
                    mr.line_text = line;
                    if (mr.line_text.size() > 512) mr.line_text.resize(512);

                    std::lock_guard<std::mutex> lk(st.results_mtx);
                    st.results.push_back(std::move(mr));
                    st.match_count.fetch_add(1, std::memory_order_relaxed);
                }
            } else {

                const std::string& haystack_orig = line;
                std::string haystack = line;
                const std::string& needle = case_sensitive ? query : query_lower;
                if (!case_sensitive)
                    for (auto& ch : haystack)
                        ch = static_cast<char>(tolower(static_cast<unsigned char>(ch)));

                size_t pos = 0;
                while ((pos = haystack.find(needle, pos)) != std::string::npos) {
                    bool valid = true;
                    if (whole_word) {
                        if (pos > 0 && (isalnum(static_cast<unsigned char>(haystack[pos - 1])) || haystack[pos - 1] == '_'))
                            valid = false;
                        size_t end = pos + needle.size();
                        if (end < haystack.size() && (isalnum(static_cast<unsigned char>(haystack[end])) || haystack[end] == '_'))
                            valid = false;
                    }
                    if (valid) {
                        MatchResult mr;
                        mr.filepath = path.string();
                        mr.filename = fname;
                        mr.line_number = line_no;
                        mr.col_start = static_cast<int>(pos);
                        mr.col_end = static_cast<int>(pos + needle.size());
                        mr.line_text = haystack_orig;
                        if (mr.line_text.size() > 512) mr.line_text.resize(512);

                        std::lock_guard<std::mutex> lk(st.results_mtx);
                        st.results.push_back(std::move(mr));
                        st.match_count.fetch_add(1, std::memory_order_relaxed);
                    }
                    pos += needle.size();
                    if (needle.empty()) break;
                }
            }


            if (st.match_count.load(std::memory_order_relaxed) > 50000)
                break;
        }
        if (st.match_count.load(std::memory_order_relaxed) > 50000)
            break;
    }

    st.searching.store(false, std::memory_order_release);
}


inline void start_search(const std::string& root_dir)
{
    auto& st = g_search;
    if (st.searching.load()) {
        st.cancel.store(true, std::memory_order_release);

        for (int i = 0; i < 50 && st.searching.load(); ++i)
            Sleep(10);
    }

    std::string query(st.query_buf);
    if (query.empty() || root_dir.empty())
        return;

    st.cancel.store(false, std::memory_order_release);
    st.searching.store(true, std::memory_order_release);

    auto includes = parse_globs(st.include_buf);
    auto excludes = parse_globs(st.exclude_buf);

    std::thread(search_worker, root_dir, query,
                st.case_sensitive, st.whole_word, st.use_regex,
                std::move(includes), std::move(excludes)).detach();
}


inline void cancel_search()
{
    g_search.cancel.store(true, std::memory_order_release);
}

}
