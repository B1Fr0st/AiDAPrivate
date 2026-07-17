#pragma once

#include <string>
#include <string_view>
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include "../infra/executor.hpp"
#include "../infra/taskflow_runtime.hpp"
#include "../../helpers/diag_log.hpp"
#endif
#include <vector>
#include <map>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <regex>
#include <iterator>
#include <memory>
#include <system_error>
#include <utility>
#include <set>
#include <tuple>


namespace code_index {

inline std::filesystem::path path_from_utf8(std::string_view value)
{
#if defined(__cpp_char8_t)
    const auto* begin = reinterpret_cast<const char8_t*>(value.data());
    return std::filesystem::path(std::u8string(begin, begin + value.size()));
#else
    return std::filesystem::u8path(value.begin(), value.end());
#endif
}

inline std::string path_to_utf8(const std::filesystem::path& value)
{
    const auto encoded = value.generic_u8string();
#if defined(__cpp_char8_t)
    return std::string(reinterpret_cast<const char*>(encoded.data()), encoded.size());
#else
    return encoded;
#endif
}


struct symbol_t
{
    std::string file_path;
    std::string symbol_name;
    std::string symbol_type;
    int         line_number = 0;
    int         column_number = 0;
    std::string content_snippet;
};


struct search_result_t
{
    std::string file_path;
    int         line_number = 0;
    int         column_number = 0;
    int         match_length = 0;
    std::string content;
    double      score = 0.0;
};


enum class index_state_t
{
    standby,
    indexing,
    idle,
    cancelled,
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
            const std::size_t result_index = static_cast<std::size_t>(i);
            const auto& doc = _docs[scores[result_index].second];
            search_result_t r;
            r.file_path = doc.file_path;
            r.line_number = doc.line_number;
            r.content = doc.content;
            r.score = scores[result_index].first;
            results.push_back(r);
        }
        return results;
    }

    std::vector<search_result_t> lexical_search(const std::string& query,
        std::size_t maximum_results, const std::string& dir_prefix,
        const std::atomic<bool>* cancelled = nullptr) const
    {
        std::vector<search_result_t> results;
        if (query.empty() || maximum_results == 0)
            return results;
        results.reserve((std::min)(maximum_results, std::size_t{256}));
        std::string normalized_query = query;
        std::transform(normalized_query.begin(), normalized_query.end(),
            normalized_query.begin(), [](unsigned char value) {
                return static_cast<char>(std::tolower(value));
            });
        std::set<std::tuple<std::string, int, int>> emitted;
        for (const auto& document : _docs) {
            if (cancelled && cancelled->load(std::memory_order_acquire))
                break;
            if (!dir_prefix.empty()) {
                const bool prefix_matches = document.file_path.size() >= dir_prefix.size() &&
                    std::equal(dir_prefix.begin(), dir_prefix.end(),
                        document.file_path.begin(), [](unsigned char left,
                            unsigned char right) {
                            const unsigned char normalized_left = left == '\\' ? '/' : left;
                            const unsigned char normalized_right = right == '\\' ? '/' : right;
                            return std::tolower(normalized_left) ==
                                std::tolower(normalized_right);
                        });
                const bool boundary_matches = document.file_path.size() == dir_prefix.size() ||
                    (document.file_path.size() > dir_prefix.size() &&
                     (document.file_path[dir_prefix.size()] == '/' ||
                      document.file_path[dir_prefix.size()] == '\\'));
                if (!prefix_matches || !boundary_matches)
                    continue;
            }
            std::istringstream stream(document.content);
            std::string line;
            int relative_line = 0;
            while (std::getline(stream, line)) {
                if (cancelled && cancelled->load(std::memory_order_acquire))
                    return results;
                if (!line.empty() && line.back() == '\r')
                    line.pop_back();
                std::string normalized_line = line;
                std::transform(normalized_line.begin(), normalized_line.end(),
                    normalized_line.begin(), [](unsigned char value) {
                        return static_cast<char>(std::tolower(value));
                    });
                std::size_t offset = 0;
                while ((offset = normalized_line.find(normalized_query, offset)) !=
                    std::string::npos) {
                    const int exact_line = document.line_number + relative_line;
                    const int exact_column = static_cast<int>(offset) + 1;
                    if (emitted.emplace(document.file_path, exact_line,
                            exact_column).second) {
                        search_result_t result;
                        result.file_path = document.file_path;
                        result.line_number = exact_line;
                        result.column_number = exact_column;
                        result.match_length = static_cast<int>(query.size());
                        result.content = line;
                        result.score = 1.0;
                        results.push_back(std::move(result));
                        if (results.size() >= maximum_results)
                            return results;
                    }
                    offset += (std::max)(std::size_t{1}, normalized_query.size());
                }
                ++relative_line;
            }
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
        const auto& line = lines_vec[static_cast<std::size_t>(i)];
        std::smatch match;

        if (std::regex_search(line, match, class_re)) {
            symbol_t sym;
            sym.file_path = file_path;
            sym.symbol_name = match[1].str();
            sym.symbol_type = "class";
            sym.line_number = i + 1;
            sym.column_number = static_cast<int>(match.position(1)) + 1;

            int end = (std::min)(i + 5, static_cast<int>(lines_vec.size()));
            for (int j = i; j < end; ++j)
                sym.content_snippet += lines_vec[static_cast<std::size_t>(j)] + "\n";
            symbols.push_back(sym);
        }
        else if (std::regex_search(line, match, namespace_re)) {
            symbol_t sym;
            sym.file_path = file_path;
            sym.symbol_name = match[1].str();
            sym.symbol_type = "namespace";
            sym.line_number = i + 1;
            sym.column_number = static_cast<int>(match.position(1)) + 1;
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
            sym.column_number = static_cast<int>(match.position(1)) + 1;

            int end = (std::min)(i + 10, static_cast<int>(lines_vec.size()));
            for (int j = i; j < end; ++j)
                sym.content_snippet += lines_vec[static_cast<std::size_t>(j)] + "\n";
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


struct published_index_t
{
    std::uint64_t generation = 0;
    std::string root_path;
    std::shared_ptr<const bm25_index_t> index;
    std::shared_ptr<const std::vector<symbol_t>> symbols;
    std::shared_ptr<const std::vector<std::string>> file_paths;
    std::size_t indexed_files = 0;
    std::size_t indexed_bytes = 0;
    std::size_t skipped_files = 0;
    bool truncated = false;
};

class manager_t
{
public:
    explicit manager_t(const std::string& workspace_root)
        : state_(std::make_shared<runtime_state_t>(workspace_root)) {}

    index_state_t state() const noexcept
    {
        return state_->status.load(std::memory_order_acquire);
    }

    bool running() const noexcept
    {
        return state_->running.load(std::memory_order_acquire);
    }

    std::uint64_t generation() const noexcept
    {
        return state_->generation.load(std::memory_order_acquire);
    }

    std::uint64_t task_id() const noexcept
    {
        return state_->task_id.load(std::memory_order_acquire);
    }

    std::string status_detail() const
    {
        const auto detail = std::atomic_load_explicit(&state_->detail,
            std::memory_order_acquire);
        return detail ? *detail : std::string{};
    }

    std::uint64_t start_indexing()
    {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        state_->running.store(false, std::memory_order_release);
        state_->task_id.store(0, std::memory_order_release);
        state_->status.store(index_state_t::standby, std::memory_order_release);
        set_detail(state_, "Workspace text indexing is available in the native standalone runtime");
        return 0;
#else
        bool expected = false;
        if (!state_->running.compare_exchange_strong(expected, true,
                std::memory_order_acq_rel, std::memory_order_acquire))
            return state_->task_id.load(std::memory_order_acquire);

        const std::uint64_t generation_value =
            state_->generation.fetch_add(1, std::memory_order_acq_rel) + 1;
        state_->stop.store(false, std::memory_order_release);
        state_->task_id.store(0, std::memory_order_release);
        state_->indexed_documents.store(0, std::memory_order_release);
        state_->indexed_files.store(0, std::memory_order_release);
        state_->indexed_bytes.store(0, std::memory_order_release);
        state_->status.store(index_state_t::indexing, std::memory_order_release);
        set_detail(state_, "Indexing workspace text and C/C++ symbols");

        auto shared = state_;
        aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "analysis";
        sub.label = "analysis.code_index.index_workspace";
        sub.thread_class = "bounded_task";
        sub.domain = aida::infra::executor::domain_t::feature_worker;
        sub.priority = 3;
        sub.cancel_hook = [shared]() {
            shared->stop.store(true, std::memory_order_release);
            shared->status.store(index_state_t::cancelled, std::memory_order_release);
            shared->running.store(false, std::memory_order_release);
            shared->task_id.store(0, std::memory_order_release);
            set_detail(shared,
                "Workspace indexing was cancelled; the previous publication remains available");
        };
        sub.body = [shared, generation_value]() {
            const DWORD tid = GetCurrentThreadId();
            const ULONGLONG start_ms = GetTickCount64();
            diag::log_tagged_fmt("code_index", "worker_enter tid=%lu generation=%llu",
                static_cast<unsigned long>(tid),
                static_cast<unsigned long long>(generation_value));
            try {
                index_workspace(shared, generation_value);
            } catch (const std::exception& exception) {
                shared->status.store(index_state_t::error, std::memory_order_release);
                set_detail(shared, std::string("Workspace indexing failed: ") + exception.what());
                diag::log_tagged_fmt("code_index",
                    "worker_exception generation=%llu reason='%.512s'",
                    static_cast<unsigned long long>(generation_value), exception.what());
            } catch (...) {
                shared->status.store(index_state_t::error, std::memory_order_release);
                set_detail(shared, "Workspace indexing failed with an unknown exception");
                diag::log_tagged_fmt("code_index",
                    "worker_exception generation=%llu reason=unknown",
                    static_cast<unsigned long long>(generation_value));
            }
            shared->task_id.store(0, std::memory_order_release);
            shared->running.store(false, std::memory_order_release);
            diag::log_tagged_fmt("code_index",
                "worker_exit tid=%lu generation=%llu elapsed_ms=%llu state=%d files=%llu documents=%llu bytes=%llu",
                static_cast<unsigned long>(tid),
                static_cast<unsigned long long>(generation_value),
                static_cast<unsigned long long>(GetTickCount64() - start_ms),
                static_cast<int>(shared->status.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(shared->indexed_files.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(shared->indexed_documents.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(shared->indexed_bytes.load(std::memory_order_acquire)));
        };

        aida::infra::executor::submit_result_t submitted;
        try {
            submitted = aida::infra::executor::submit(std::move(sub));
        } catch (const std::exception& exception) {
            state_->status.store(index_state_t::error, std::memory_order_release);
            state_->running.store(false, std::memory_order_release);
            set_detail(state_, std::string("The workspace index could not be queued: ") +
                exception.what());
            return 0;
        } catch (...) {
            state_->status.store(index_state_t::error, std::memory_order_release);
            state_->running.store(false, std::memory_order_release);
            set_detail(state_, "The workspace index could not be queued");
            return 0;
        }
        if (!submitted.submitted) {
            const auto qs = aida::infra::taskflow_runtime::active_snapshot();
            diag::log_tagged_fmt("code_index",
                "worker_post_failed accepting=%d shutdown=%d work_pending=%llu work_active=%u submitted=%llu rejected=%llu",
                qs.accepting ? 1 : 0,
                qs.shutting_down ? 1 : 0,
                static_cast<unsigned long long>(qs.work_queue_pending),
                qs.work_queue_active,
                static_cast<unsigned long long>(qs.total_submitted),
                static_cast<unsigned long long>(qs.total_rejected));
            state_->status.store(index_state_t::error, std::memory_order_release);
            state_->running.store(false, std::memory_order_release);
            set_detail(state_, submitted.reject_reason.empty()
                ? "The workspace index could not be queued"
                : "The workspace index could not be queued: " + submitted.reject_reason);
            return 0;
        }

        state_->task_id.store(submitted.task_id, std::memory_order_release);
        if (!state_->running.load(std::memory_order_acquire)) {
            std::uint64_t completed_task = submitted.task_id;
            state_->task_id.compare_exchange_strong(completed_task, 0,
                std::memory_order_acq_rel, std::memory_order_acquire);
        }
        if (state_->stop.load(std::memory_order_acquire))
            aida::infra::executor::cancel(submitted.task_id);
        return submitted.task_id;
#endif
    }

    void stop_indexing() noexcept
    {
        state_->stop.store(true, std::memory_order_release);
        const std::uint64_t active_task = state_->task_id.load(std::memory_order_acquire);
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
        if (active_task != 0)
            aida::infra::executor::cancel(active_task);
#else
        static_cast<void>(active_task);
#endif
    }

    std::vector<search_result_t> search(const std::string& query,
        const std::string& directory = "", int top_k = 10) const
    {
        const auto publication = std::atomic_load_explicit(&state_->publication,
            std::memory_order_acquire);
        if (!publication || !publication->index)
            return {};
        return publication->index->search(query, (std::max)(0, top_k), directory);
    }

    std::shared_ptr<const published_index_t> snapshot() const noexcept
    {
        return std::atomic_load_explicit(&state_->publication, std::memory_order_acquire);
    }

    std::size_t indexed_count() const noexcept
    {
        return state_->indexed_documents.load(std::memory_order_acquire);
    }

    std::size_t indexed_file_count() const noexcept
    {
        return state_->indexed_files.load(std::memory_order_acquire);
    }

    std::size_t indexed_byte_count() const noexcept
    {
        return state_->indexed_bytes.load(std::memory_order_acquire);
    }

    ~manager_t()
    {
        stop_indexing();
    }

private:
    struct runtime_state_t
    {
        explicit runtime_state_t(std::string root) : workspace(std::move(root)) {}

        std::string workspace;
        std::atomic<index_state_t> status{index_state_t::standby};
        std::atomic<bool> stop{false};
        std::atomic<bool> running{false};
        std::atomic<std::uint64_t> generation{0};
        std::atomic<std::uint64_t> task_id{0};
        std::atomic<std::size_t> indexed_documents{0};
        std::atomic<std::size_t> indexed_files{0};
        std::atomic<std::size_t> indexed_bytes{0};
        std::shared_ptr<const published_index_t> publication;
        std::shared_ptr<const std::string> detail;
    };

    std::shared_ptr<runtime_state_t> state_;

    static void set_detail(const std::shared_ptr<runtime_state_t>& shared,
        std::string detail)
    {
        std::atomic_store_explicit(&shared->detail,
            std::make_shared<const std::string>(std::move(detail)),
            std::memory_order_release);
    }

    static std::vector<std::string> tokenize_lines(const std::string& text)
    {
        std::vector<std::string> lines;
        std::istringstream stream(text);
        std::string line;
        while (std::getline(stream, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            lines.push_back(std::move(line));
        }
        return lines;
    }

    static void index_workspace(const std::shared_ptr<runtime_state_t>& shared,
        std::uint64_t generation_value)
    {
        constexpr std::uintmax_t maximum_file_bytes = 1024U * 1024U;
        constexpr std::size_t maximum_indexed_files = 250000U;
        constexpr std::size_t maximum_visited_entries = 1000000U;
        constexpr std::size_t maximum_indexed_bytes = 256U * 1024U * 1024U;
        constexpr std::size_t maximum_documents = 500000U;
        constexpr int chunk_size = 20;
        constexpr int chunk_stride = 10;

        auto new_index = std::make_shared<bm25_index_t>();
        auto symbols = std::make_shared<std::vector<symbol_t>>();
        symbols->reserve(4096);
        auto file_paths = std::make_shared<std::vector<std::string>>();
        file_paths->reserve(4096);
        std::size_t indexed_files = 0;
        std::size_t indexed_bytes = 0;
        std::size_t indexed_documents = 0;
        std::size_t skipped_files = 0;
        std::size_t visited_entries = 0;
        bool truncated = false;

        const std::filesystem::path workspace_path =
            path_from_utf8(shared->workspace).lexically_normal();
        bool workspace_root_acceptable = workspace_path.is_absolute();
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
        const DWORD workspace_attributes = GetFileAttributesW(workspace_path.c_str());
        workspace_root_acceptable = workspace_root_acceptable &&
            workspace_attributes != INVALID_FILE_ATTRIBUTES &&
            (workspace_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
            (workspace_attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
#endif
        if (!workspace_root_acceptable) {
            shared->status.store(index_state_t::error, std::memory_order_release);
            set_detail(shared,
                "The workspace root must be an accessible absolute non-reparse directory");
            return;
        }

        std::error_code ec;
        const auto opts = std::filesystem::directory_options::skip_permission_denied;
        std::filesystem::recursive_directory_iterator iter(workspace_path, opts, ec);
        const std::filesystem::recursive_directory_iterator end_iter;
        if (ec) {
            shared->status.store(index_state_t::error, std::memory_order_release);
            set_detail(shared, "The workspace root could not be enumerated: " + ec.message());
            return;
        }

        while (iter != end_iter) {
            if (shared->stop.load(std::memory_order_acquire)) {
                shared->status.store(index_state_t::cancelled, std::memory_order_release);
                set_detail(shared, "Workspace indexing was cancelled; the previous publication remains available");
                return;
            }
            if (visited_entries >= maximum_visited_entries ||
                indexed_files >= maximum_indexed_files ||
                indexed_bytes >= maximum_indexed_bytes ||
                indexed_documents >= maximum_documents) {
                truncated = true;
                break;
            }
            ++visited_entries;

            const auto& entry = *iter;
            std::error_code entry_ec;
            const bool symlink = entry.is_symlink(entry_ec) && !entry_ec;
            bool reparse_point = false;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
            const DWORD attributes = GetFileAttributesW(entry.path().c_str());
            reparse_point = attributes != INVALID_FILE_ATTRIBUTES &&
                (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#endif
            if (symlink || reparse_point) {
                entry_ec.clear();
                if (entry.is_directory(entry_ec) && !entry_ec)
                    iter.disable_recursion_pending();
            }
            entry_ec.clear();
            if (!symlink && !reparse_point &&
                entry.is_regular_file(entry_ec) && !entry_ec) {
                std::string ext = path_to_utf8(entry.path().extension());
                std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char value) {
                    return static_cast<char>(std::tolower(value));
                });
                if (is_indexable_extension(ext)) {
                    std::error_code size_error;
                    const std::uintmax_t file_bytes = entry.file_size(size_error);
                    if (!size_error && file_bytes <= maximum_file_bytes &&
                        file_bytes <= maximum_indexed_bytes - indexed_bytes) {
                        std::ifstream input(entry.path(), std::ios::binary);
                        if (input) {
                            std::string content(static_cast<std::size_t>(file_bytes), '\0');
                            if (!content.empty())
                                input.read(content.data(), static_cast<std::streamsize>(content.size()));
                            const bool exact = input.good() ||
                                (input.eof() && static_cast<std::size_t>(input.gcount()) == content.size());
                            if (exact) {
                                std::error_code relative_error;
                                std::string relative = path_to_utf8(std::filesystem::relative(
                                    entry.path(), workspace_path, relative_error));
                                if (relative_error) {
                                    ++skipped_files;
                                    relative.clear();
                                }
                                std::replace(relative.begin(), relative.end(), '\\', '/');

                                if (!relative.empty() &&
                                    (ext == ".cpp" || ext == ".c" || ext == ".h" ||
                                    ext == ".hpp" || ext == ".cc" || ext == ".cxx" ||
                                    ext == ".hxx")) {
                                    auto extracted = extract_symbols_cpp(relative, content);
                                    if (symbols->size() + extracted.size() > maximum_documents) {
                                        truncated = true;
                                        extracted.resize(maximum_documents - symbols->size());
                                    }
                                    symbols->insert(symbols->end(),
                                        std::make_move_iterator(extracted.begin()),
                                        std::make_move_iterator(extracted.end()));
                                }

                                if (!relative.empty()) {
                                    file_paths->push_back(relative);
                                    const auto lines = tokenize_lines(content);
                                    int line = 0;
                                    for (;
                                        line < static_cast<int>(lines.size()) &&
                                        indexed_documents < maximum_documents;
                                        line += chunk_stride) {
                                        const int end = (std::min)(line + chunk_size,
                                            static_cast<int>(lines.size()));
                                        std::string chunk;
                                        for (int current = line; current < end; ++current) {
                                            chunk.append(lines[static_cast<std::size_t>(current)]);
                                            chunk.push_back('\n');
                                        }
                                        new_index->add_document(relative, line + 1, chunk);
                                        ++indexed_documents;
                                    }
                                    if (line < static_cast<int>(lines.size()))
                                        truncated = true;
                                    ++indexed_files;
                                    indexed_bytes += content.size();
                                    shared->indexed_files.store(indexed_files, std::memory_order_release);
                                    shared->indexed_bytes.store(indexed_bytes, std::memory_order_release);
                                    shared->indexed_documents.store(indexed_documents, std::memory_order_release);
                                }
                            } else {
                                ++skipped_files;
                            }
                        } else {
                            ++skipped_files;
                        }
                    } else {
                        ++skipped_files;
                        truncated = true;
                    }
                }
            }

            std::error_code increment_error;
            iter.increment(increment_error);
            if (increment_error) {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
                diag::log_tagged_fmt("code_index", "enumeration_skip error='%s'",
                    increment_error.message().c_str());
#endif
                ++skipped_files;
                truncated = true;
                break;
            }
        }

        if (shared->stop.load(std::memory_order_acquire)) {
            shared->status.store(index_state_t::cancelled, std::memory_order_release);
            set_detail(shared, "Workspace indexing was cancelled; the previous publication remains available");
            return;
        }

        new_index->build();
        if (shared->stop.load(std::memory_order_acquire)) {
            shared->status.store(index_state_t::cancelled, std::memory_order_release);
            set_detail(shared, "Workspace indexing was cancelled; the previous publication remains available");
            return;
        }
        indexed_documents = new_index->document_count();
        shared->indexed_documents.store(indexed_documents, std::memory_order_release);
        auto publication = std::make_shared<published_index_t>();
        publication->generation = generation_value;
        publication->root_path = path_to_utf8(workspace_path);
        publication->index = std::move(new_index);
        publication->symbols = std::move(symbols);
        std::sort(file_paths->begin(), file_paths->end());
        publication->file_paths = std::move(file_paths);
        publication->indexed_files = indexed_files;
        publication->indexed_bytes = indexed_bytes;
        publication->skipped_files = skipped_files;
        publication->truncated = truncated;
        std::atomic_store_explicit(&shared->publication,
            std::shared_ptr<const published_index_t>(std::move(publication)),
            std::memory_order_release);
        shared->status.store(index_state_t::idle, std::memory_order_release);
        set_detail(shared, truncated || skipped_files != 0
            ? "Workspace index is ready with bounded or skipped files"
            : "Workspace index is ready");
    }
};


}
