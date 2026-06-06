#pragma once

#include <string>
#include "work_queue.hpp"
#include "../infra/win_thread.hpp"
#include <vector>
#include <map>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <thread>
#include <condition_variable>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <regex>
#include <functional>
#include <system_error>
#include <utility>


namespace code_index {


struct symbol_t
{
    std::string file_path;
    std::string symbol_name;
    std::string symbol_type;
    int         line_number = 0;
    std::string content_snippet;
};


struct search_result_t
{
    std::string file_path;
    int         line_number = 0;
    std::string content;
    double      score = 0.0;
};


enum class index_state_t
{
    standby,
    indexing,
    idle,
    error
};


inline std::vector<std::string> tokenize(const std::string& text)
{
    std::vector<std::string> tokens;
    std::string current;
    for (char c : text) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') {
            current += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        } else {
            if (!current.empty()) {
                tokens.push_back(current);
                current.clear();
            }
        }
    }
    if (!current.empty())
        tokens.push_back(current);
    return tokens;
}


struct document_t
{
    std::string file_path;
    int         line_number = 0;
    std::string content;
    std::map<std::string, double> tf;
    double dl = 0.0;
};


class bm25_index_t
{
public:
    static constexpr double K1 = 1.2;
    static constexpr double B  = 0.75;

    void clear()
    {
        _docs.clear();
        _idf.clear();
        _avg_dl = 0.0;
    }

    void add_document(const std::string& file_path, int line, const std::string& content)
    {
        document_t doc;
        doc.file_path = file_path;
        doc.line_number = line;
        doc.content = content;

        auto tokens = tokenize(content);
        if (tokens.empty()) return;

        std::map<std::string, int> freq;
        for (const auto& t : tokens) freq[t]++;

        doc.dl = static_cast<double>(tokens.size());
        for (const auto& [term, count] : freq) {
            doc.tf[term] = static_cast<double>(count) / doc.dl;
        }

        _docs.push_back(std::move(doc));
    }

    void build()
    {
        if (_docs.empty()) return;

        double total_dl = 0.0;
        std::map<std::string, int> df;

        for (const auto& doc : _docs) {
            total_dl += doc.dl;
            for (const auto& [term, _] : doc.tf) {
                df[term]++;
            }
        }

        _avg_dl = total_dl / static_cast<double>(_docs.size());

        double n = static_cast<double>(_docs.size());
        for (const auto& [term, count] : df) {
            _idf[term] = std::log((n - count + 0.5) / (count + 0.5) + 1.0);
        }
    }

    std::vector<search_result_t> search(const std::string& query, int top_k = 10, const std::string& dir_prefix = "") const
    {
        auto query_tokens = tokenize(query);
        if (query_tokens.empty()) return {};

        std::vector<std::pair<double, size_t>> scores;
        scores.reserve(_docs.size());

        for (size_t i = 0; i < _docs.size(); ++i) {
            if (!dir_prefix.empty() && _docs[i].file_path.find(dir_prefix) != 0)
                continue;

            double score = 0.0;
            const double dl = _docs[i].dl;
            const double avg_dl = (_avg_dl > 0.0) ? _avg_dl : 1.0;

            for (const auto& qt : query_tokens) {
                auto idf_it = _idf.find(qt);
                if (idf_it == _idf.end()) continue;

                auto tf_it = _docs[i].tf.find(qt);
                double tf_val = (tf_it != _docs[i].tf.end()) ? tf_it->second * dl : 0.0;

                double numerator = tf_val * (K1 + 1.0);
                double denominator = tf_val + K1 * (1.0 - B + B * dl / avg_dl);
                if (denominator <= 0.0) continue;
                score += idf_it->second * (numerator / denominator);
            }

            if (score > 0.0)
                scores.emplace_back(score, i);
        }

        std::sort(scores.begin(), scores.end(),
                  [](const auto& a, const auto& b) { return a.first > b.first; });

        std::vector<search_result_t> results;
        int count = (std::min)(top_k, static_cast<int>(scores.size()));
        for (int i = 0; i < count; ++i) {
            const auto& doc = _docs[scores[i].second];
            search_result_t r;
            r.file_path = doc.file_path;
            r.line_number = doc.line_number;
            r.content = doc.content;
            r.score = scores[i].first;
            results.push_back(r);
        }
        return results;
    }

    size_t document_count() const { return _docs.size(); }

private:
    std::vector<document_t> _docs;
    std::map<std::string, double> _idf;
    double _avg_dl = 0.0;
};


inline std::vector<symbol_t> extract_symbols_cpp(const std::string& file_path, const std::string& content)
{
    std::vector<symbol_t> symbols;
    auto lines_vec = [&]() {
        std::vector<std::string> lines;
        std::istringstream stream(content);
        std::string line;
        while (std::getline(stream, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            lines.push_back(line);
        }
        return lines;
    }();

    static const std::regex func_re(R"((?:[\w:]+\s+)+(\w+)\s*\([^)]*\)\s*\{?)");
    static const std::regex class_re(R"((?:class|struct)\s+(\w+))");
    static const std::regex namespace_re(R"(namespace\s+(\w+))");

    for (int i = 0; i < static_cast<int>(lines_vec.size()); ++i) {
        const auto& line = lines_vec[i];
        std::smatch match;

        if (std::regex_search(line, match, class_re)) {
            symbol_t sym;
            sym.file_path = file_path;
            sym.symbol_name = match[1].str();
            sym.symbol_type = "class";
            sym.line_number = i + 1;

            int end = (std::min)(i + 5, static_cast<int>(lines_vec.size()));
            for (int j = i; j < end; ++j)
                sym.content_snippet += lines_vec[j] + "\n";
            symbols.push_back(sym);
        }
        else if (std::regex_search(line, match, namespace_re)) {
            symbol_t sym;
            sym.file_path = file_path;
            sym.symbol_name = match[1].str();
            sym.symbol_type = "namespace";
            sym.line_number = i + 1;
            sym.content_snippet = line;
            symbols.push_back(sym);
        }
        else if (std::regex_search(line, match, func_re)) {
            std::string name = match[1].str();
            if (name == "if" || name == "for" || name == "while" || name == "switch" ||
                name == "return" || name == "else" || name == "catch" || name == "throw")
                continue;

            symbol_t sym;
            sym.file_path = file_path;
            sym.symbol_name = name;
            sym.symbol_type = "function";
            sym.line_number = i + 1;

            int end = (std::min)(i + 10, static_cast<int>(lines_vec.size()));
            for (int j = i; j < end; ++j)
                sym.content_snippet += lines_vec[j] + "\n";
            symbols.push_back(sym);
        }
    }

    return symbols;
}


inline bool is_indexable_extension(const std::string& ext)
{
    static const std::vector<std::string> exts = {
        ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx",
        ".py", ".js", ".ts", ".jsx", ".tsx",
        ".java", ".rs", ".go", ".cs", ".rb",
        ".lua", ".asm", ".s",
        ".json", ".yaml", ".yml", ".toml",
        ".md", ".txt"
    };
    for (const auto& e : exts)
        if (ext == e) return true;
    return false;
}


class manager_t
{
public:
    explicit manager_t(const std::string& workspace_root)
        : _workspace(workspace_root) {}

    index_state_t state() const { return _state.load(); }

    void start_indexing()
    {
        if (_running.load()) return;
        _state = index_state_t::indexing;
        _stop = false;
        _running = true;

        auto index_task = [this]() {
            index_workspace();
            {
                std::lock_guard<std::mutex> lk(_done_mtx);
                _running = false;
            }
            _done_cv.notify_all();
        };
        std::string thread_error;
        if (!aida::infra::win_thread::start_detached(index_task, &thread_error, aida::infra::win_thread::default_stack_reserve, "code-index.worker")) {
            if (!work_queue::post(std::move(index_task))) {
                _state = index_state_t::error;
                _running = false;
                _done_cv.notify_all();
            }
        }
    }

    void stop_indexing()
    {
        _stop = true;
        std::unique_lock<std::mutex> lk(_done_mtx);
        _done_cv.wait(lk, [this]() { return !_running.load(); });
    }

    std::vector<search_result_t> search(const std::string& query, const std::string& directory = "", int top_k = 10) const
    {
        std::lock_guard<std::mutex> lk(_mtx);
        return _index.search(query, top_k, directory);
    }

    size_t indexed_count() const
    {
        std::lock_guard<std::mutex> lk(_mtx);
        return _index.document_count();
    }

    ~manager_t()
    {
        _stop = true;
        std::unique_lock<std::mutex> lk(_done_mtx);
        _done_cv.wait(lk, [this]() { return !_running.load(); });
    }

private:
    std::string _workspace;
    mutable std::mutex _mtx;
    bm25_index_t _index;
    std::atomic<index_state_t> _state{index_state_t::standby};
    std::atomic<bool> _stop{false};
    std::atomic<bool> _running{false};
    std::mutex _done_mtx;
    std::condition_variable _done_cv;

    void index_workspace()
    {
        bm25_index_t new_index;

        std::error_code ec;
        const auto opts = std::filesystem::directory_options::skip_permission_denied;
        std::filesystem::recursive_directory_iterator iter(_workspace, opts, ec);
        std::filesystem::recursive_directory_iterator end_iter;

        if (ec) {
            _state = index_state_t::error;
            return;
        }

        while (iter != end_iter) {
            if (_stop.load()) break;

            const auto& entry = *iter;
            std::error_code entry_ec;

            if (entry.is_regular_file(entry_ec) && !entry_ec) {
                auto ext = entry.path().extension().string();
                if (is_indexable_extension(ext)) {
                    std::error_code sz_ec;
                    auto fsize = entry.file_size(sz_ec);
                    if (!sz_ec && fsize <= 1024 * 1024) {
                        std::ifstream ifs(entry.path(), std::ios::binary);
                        if (ifs) {
                            std::string content((std::istreambuf_iterator<char>(ifs)),
                                                 std::istreambuf_iterator<char>());

                            std::error_code rel_ec;
                            auto rel = std::filesystem::relative(entry.path(), _workspace, rel_ec).string();
                            if (rel_ec) rel = entry.path().string();
                            std::replace(rel.begin(), rel.end(), '\\', '/');

                            if (ext == ".cpp" || ext == ".c" || ext == ".h" || ext == ".hpp" ||
                                ext == ".cc" || ext == ".cxx" || ext == ".hxx") {
                                auto symbols = extract_symbols_cpp(rel, content);
                                for (const auto& sym : symbols) {
                                    new_index.add_document(sym.file_path, sym.line_number, sym.content_snippet);
                                }
                            }

                            auto lines = tokenize_lines(content);
                            int chunk_size = 20;
                            for (int i = 0; i < static_cast<int>(lines.size()); i += chunk_size / 2) {
                                int end = (std::min)(i + chunk_size, static_cast<int>(lines.size()));
                                std::string chunk;
                                for (int j = i; j < end; ++j)
                                    chunk += lines[j] + "\n";
                                new_index.add_document(rel, i + 1, chunk);
                            }
                        }
                    }
                }
            }

            std::error_code inc_ec;
            iter.increment(inc_ec);
            if (inc_ec) {
                iter = end_iter;
                break;
            }
        }

        new_index.build();

        {
            std::lock_guard<std::mutex> lk(_mtx);
            _index = std::move(new_index);
        }

        _state = index_state_t::idle;
    }

    static std::vector<std::string> tokenize_lines(const std::string& text)
    {
        std::vector<std::string> lines;
        std::istringstream stream(text);
        std::string line;
        while (std::getline(stream, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            lines.push_back(line);
        }
        return lines;
    }
};


}
