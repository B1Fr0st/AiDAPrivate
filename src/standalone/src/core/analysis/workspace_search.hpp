#pragma once


#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include "../infra/executor.hpp"
#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <regex>
#include <string>
#include <utility>
#include <vector>

namespace workspace_search
{


struct match_result_t
{
    std::string filepath;
    std::string filename;
    int         line_number;
    int         col_start;
    int         col_end;
    std::string line_text;
};


struct search_state_t
{

    char            query_buf[512]  = {};
    char            include_buf[256] = {};
    char            exclude_buf[256] = {};
    bool            case_sensitive   = false;
    bool            whole_word       = false;
    bool            use_regex        = false;


    std::mutex                    results_mtx;
    std::vector<match_result_t>   results;
    int                           selected_idx = -1;


    std::atomic<bool>             searching{false};
    std::atomic<bool>             cancel{false};
    std::atomic<bool>             launch_pending{false};
    std::atomic<int>              files_scanned{0};
    std::atomic<int>              match_count{0};
    std::atomic<std::uint64_t>    generation{0};
    std::atomic<bool>             truncated{false};


    bool                          panel_open = false;
};

inline search_state_t g_search;


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


inline std::vector<std::string> load_aidaignore_patterns(const std::string& root_dir)
{
    std::vector<std::string> patterns;
    std::error_code ec;
    auto ignore_path = std::filesystem::path(root_dir) / ".aidaignore";
    if (!std::filesystem::exists(ignore_path, ec)) return patterns;
    std::ifstream ifs(ignore_path);
    if (!ifs.is_open()) return patterns;
    std::string line;
    while (std::getline(ifs, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' '))
            line.pop_back();
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t'))
            line.erase(line.begin());
        if (line.empty() || line.front() == '#') continue;
        patterns.push_back(std::move(line));
    }
    return patterns;
}

inline bool path_matches_aidaignore(const std::string& full_path,
                                    const std::string& root_dir,
                                    const std::vector<std::string>& patterns)
{
    if (patterns.empty()) return false;
    std::string rel;
    if (full_path.size() > root_dir.size() &&
        std::memcmp(full_path.data(), root_dir.data(), root_dir.size()) == 0) {
        rel = full_path.substr(root_dir.size());
        while (!rel.empty() && (rel.front() == '\\' || rel.front() == '/'))
            rel.erase(rel.begin());
    } else {
        rel = full_path;
    }
    std::string rel_fwd = rel;
    for (auto& c : rel_fwd) if (c == '\\') c = '/';
    std::filesystem::path p(rel);
    std::string fname = p.filename().string();
    for (const auto& pat : patterns) {
        if (glob_match(pat, fname)) return true;
        if (glob_match(pat, rel_fwd)) return true;
        if (pat.find('/') == std::string::npos) {
            size_t slash = 0;
            while (slash != std::string::npos) {
                size_t next = rel_fwd.find('/', slash);
                std::string segment = rel_fwd.substr(slash, next == std::string::npos ? std::string::npos : next - slash);
                if (glob_match(pat, segment)) return true;
                if (next == std::string::npos) break;
                slash = next + 1;
            }
        }
    }
    return false;
}

inline void search_worker(std::vector<std::string> root_dirs, std::string query,
                          bool case_sensitive, bool whole_word, bool use_regex,
                          std::vector<std::string> include_globs,
                          std::vector<std::string> exclude_globs,
                          std::uint64_t generation)
{
    auto& st = g_search;
    if (generation != st.generation.load(std::memory_order_acquire))
        return;
    const auto cancelled = [&st, generation]() {
        return st.cancel.load(std::memory_order_acquire) ||
            generation != st.generation.load(std::memory_order_acquire);
    };
    st.files_scanned.store(0);
    st.match_count.store(0);
    st.truncated.store(false, std::memory_order_release);
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
            re.assign(query, flags);
        } catch (const std::regex_error&) {
            if (generation == st.generation.load(std::memory_order_acquire))
                st.searching.store(false, std::memory_order_release);
            return;
        } catch (...) {
            if (generation == st.generation.load(std::memory_order_acquire))
                st.searching.store(false, std::memory_order_release);
            return;
        }
    }


    std::string query_lower = query;
    if (!case_sensitive)
        for (auto& ch : query_lower)
            ch = static_cast<char>(tolower(static_cast<unsigned char>(ch)));

    for (const auto& root_dir : root_dirs) {
        if (cancelled()) break;
        const auto aidaignore = load_aidaignore_patterns(root_dir);
        std::error_code ec;
        auto end_it = std::filesystem::recursive_directory_iterator();
        auto it = std::filesystem::recursive_directory_iterator(root_dir,
            std::filesystem::directory_options::skip_permission_denied, ec);
        while (it != end_it)
        {
        if (cancelled())
            break;
        if (st.files_scanned.load(std::memory_order_relaxed) >= 1000000) {
            st.truncated.store(true, std::memory_order_release);
            break;
        }

        bool skip_iteration = false;

        if (!it->is_regular_file(ec)) {
            skip_iteration = true;
        }

        std::filesystem::path path;
        std::string ext, fname, ps;

        if (!skip_iteration) {
            path = it->path();
            ext = path.extension().string();
            fname = path.filename().string();
            ps = path.string();

            if (!is_text_extension(ext) && !ext.empty())
                skip_iteration = true;
        }

        if (!skip_iteration && !include_globs.empty()) {
            bool match = false;
            for (const auto& g : include_globs)
                if (glob_match(g, fname)) { match = true; break; }
            if (!match) skip_iteration = true;
        }

        if (!skip_iteration) {
            for (const auto& g : exclude_globs)
                if (glob_match(g, fname)) { skip_iteration = true; break; }
        }

        if (!skip_iteration) {
            if (ps.find("\\.git\\") != std::string::npos ||
                ps.find("\\node_modules\\") != std::string::npos ||
                ps.find("\\__pycache__\\") != std::string::npos ||
                ps.find("\\.vs\\") != std::string::npos ||
                ps.find("\\Release\\") != std::string::npos ||
                ps.find("\\Debug\\") != std::string::npos)
                skip_iteration = true;
        }

        if (!skip_iteration && path_matches_aidaignore(ps, root_dir, aidaignore))
            skip_iteration = true;

        if (skip_iteration) {
            it.increment(ec);
            if (ec) break;
            continue;
        }

        std::error_code size_error;
        const auto source_size = std::filesystem::file_size(path, size_error);
        if (size_error || source_size > 16ULL * 1024ULL * 1024ULL) {
            it.increment(ec);
            if (ec) break;
            continue;
        }
        std::ifstream ifs(path, std::ios::in);
        if (!ifs.is_open()) {
            it.increment(ec);
            if (ec) break;
            continue;
        }

        st.files_scanned.fetch_add(1, std::memory_order_relaxed);

        std::string line;
        int line_no = 0;
        while (std::getline(ifs, line)) {
            ++line_no;
            if (cancelled())
                break;

            if (use_regex) {
                std::smatch sm;
                if (std::regex_search(line, sm, re)) {
                    match_result_t mr;
                    mr.filepath = path.string();
                    mr.filename = fname;
                    mr.line_number = line_no;
                    mr.col_start = static_cast<int>(sm.position(0));
                    mr.col_end = mr.col_start + static_cast<int>(sm.length(0));
                    mr.line_text = line;
                    if (mr.line_text.size() > 512) mr.line_text.resize(512);

                    std::lock_guard<std::mutex> lk(st.results_mtx);
                    if (!cancelled() && st.results.size() < 50000) {
                        st.results.push_back(std::move(mr));
                        st.match_count.fetch_add(1, std::memory_order_relaxed);
                    }
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
                        match_result_t mr;
                        mr.filepath = path.string();
                        mr.filename = fname;
                        mr.line_number = line_no;
                        mr.col_start = static_cast<int>(pos);
                        mr.col_end = static_cast<int>(pos + needle.size());
                        mr.line_text = haystack_orig;
                        if (mr.line_text.size() > 512) mr.line_text.resize(512);

                        std::lock_guard<std::mutex> lk(st.results_mtx);
                        if (!cancelled() && st.results.size() < 50000) {
                            st.results.push_back(std::move(mr));
                            st.match_count.fetch_add(1, std::memory_order_relaxed);
                        }
                    }
                    pos += needle.size();
                    if (needle.empty()) break;
                }
            }


            if (st.match_count.load(std::memory_order_relaxed) >= 50000)
            {
                st.truncated.store(true, std::memory_order_release);
                break;
            }
        }
        if (st.match_count.load(std::memory_order_relaxed) >= 50000)
        {
            st.truncated.store(true, std::memory_order_release);
            break;
        }

        it.increment(ec);
        if (ec) break;
        }
        if (st.truncated.load(std::memory_order_acquire) ||
            st.match_count.load(std::memory_order_relaxed) >= 50000)
            break;
    }

    if (generation == st.generation.load(std::memory_order_acquire))
        st.searching.store(false, std::memory_order_release);
}


inline void start_search(std::vector<std::string> root_dirs)
{
    auto& st = g_search;

    std::string query(st.query_buf);
    root_dirs.erase(std::remove_if(root_dirs.begin(), root_dirs.end(),
        [](const std::string& root) { return root.empty(); }), root_dirs.end());
    if (root_dirs.size() > 8) root_dirs.resize(8);
    if (query.empty() || root_dirs.empty())
        return;

    bool expected_pending = false;
    if (!st.launch_pending.compare_exchange_strong(expected_pending, true, std::memory_order_acq_rel))
        return;

    if (st.searching.load(std::memory_order_acquire))
        st.cancel.store(true, std::memory_order_release);

    const std::uint64_t generation = st.generation.fetch_add(1, std::memory_order_acq_rel) + 1;

    bool case_sensitive = st.case_sensitive;
    bool whole_word     = st.whole_word;
    bool use_regex      = st.use_regex;
    auto includes       = parse_globs(st.include_buf);
    auto excludes       = parse_globs(st.exclude_buf);

    aida::infra::executor::submission_t sub;
    sub.owner_subsystem = "analysis";
    sub.label = "analysis.workspace_search";
    sub.thread_class = "bounded_task";
    sub.domain = aida::infra::executor::domain_t::feature_worker;
    sub.priority = 3;
    sub.generation = generation;
    sub.body = [root_dirs = std::move(root_dirs),
                query = std::move(query),
                case_sensitive, whole_word, use_regex,
                includes = std::move(includes),
                excludes = std::move(excludes), generation]() mutable {
        auto& s = g_search;
        if (generation != s.generation.load(std::memory_order_acquire))
            return;
        s.cancel.store(false, std::memory_order_release);
        s.searching.store(true, std::memory_order_release);
        s.launch_pending.store(false, std::memory_order_release);

        search_worker(std::move(root_dirs), std::move(query),
                      case_sensitive, whole_word, use_regex,
                      std::move(includes), std::move(excludes), generation);
    };
    if (!aida::infra::executor::submit(std::move(sub)).submitted) {
        st.launch_pending.store(false, std::memory_order_release);
        st.searching.store(false, std::memory_order_release);
        diag::log_tagged("workspace_search", "start_search_post_failed");
    }
}

inline void start_search(const std::string& root_dir)
{
    start_search(std::vector<std::string>{root_dir});
}


inline void cancel_search()
{
    g_search.cancel.store(true, std::memory_order_release);
}

}
